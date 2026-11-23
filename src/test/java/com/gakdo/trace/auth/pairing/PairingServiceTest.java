// 이 파일이 확인하는 것: 진단 에이전트 페어링 코드 규칙.
// 관리자가 렌탈 시점에 6자리 코드를 발급 → 고객 노트북의 에이전트가 코드를 넣으면 AGENT 토큰으로 바뀐다.
// 코드는 5분 동안 한 번만 쓸 수 있고, 특정 기기 일련번호에 묶인다. 틀린 코드가 몰리면 잠시 전체를 막는다.

package com.gakdo.trace.auth.pairing;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.domain.RateLimitedException;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.pairing.application.PairingFailureGuard;
import com.gakdo.trace.auth.pairing.application.PairingService;
import com.gakdo.trace.auth.pairing.domain.PairingCode;
import com.gakdo.trace.auth.pairing.domain.PairingCodeRepository;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

class PairingServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-12T00:00:00Z");
    private static final Duration FIVE_MIN = Duration.ofMinutes(5);

    private final PairingCodeRepository codes = mock(PairingCodeRepository.class);
    private final SecureTokens tokens = mock(SecureTokens.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), FIVE_MIN, Duration.ofMinutes(30), true, null, null, null);
    private final PairingFailureGuard failures = mock(PairingFailureGuard.class);
    private final PairingService service = new PairingService(codes, tokens,
            new JwtIssuer(new SigningKeyProvider(properties), properties, clock), properties, clock, failures);
    private static final PairingFailureGuard.Attempt ATTEMPT = PairingFailureGuard.Attempt.allowed("w");

    {
        given(failures.tryAcquire()).willReturn(ATTEMPT);
    }

    // [상황] 새 코드를 뽑았는데 같은 숫자(111111)의 유효한 코드가 이미 있다.
    // [기대] 다시 뽑아 222222를 주고, 만료는 5분 뒤다.
    @Test
    @DisplayName("페어링 코드는 5분 뒤 만료되고 같은 값의 유효한 코드가 있으면 다시 뽑는다")
    void createRedrawsCollision() {
        given(tokens.sixDigitCode()).willReturn("111111", "222222");
        given(codes.existsByCodeHashAndUsedAtIsNullAndExpiresAtAfter(Sha256.hex("111111"), NOW)).willReturn(true);

        PairingService.IssuedCode issued = service.create(NanoId.next(), NanoId.next(), "C02TEST00001");

        assertThat(issued.code()).isEqualTo("222222");
        assertThat(issued.expiresAt()).isEqualTo(NOW.plus(FIVE_MIN));
    }

    // [상황] 없는 코드를 넣고, 만료된 코드를 넣는다.
    // [기대] 없으면 400 PAIRING_CODE_INVALID, 만료면 410 PAIRING_CODE_EXPIRED.
    @Test
    @DisplayName("없는 코드는 400, 만료된 코드는 410이다")
    void exchangeFailures() {
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(any())).willReturn(Optional.empty());
        assertThatThrownBy(() -> service.exchange("000000"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_INVALID);

        PairingCode expired = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("123456"),
                NOW.minusSeconds(1), NOW.minus(FIVE_MIN));
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("123456"))).willReturn(Optional.of(expired));
        assertThatThrownBy(() -> service.exchange("123456"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_EXPIRED);
    }

    // [상황] 같은 코드를 두 곳에서 동시에 넣어 다른 쪽이 먼저 썼다.
    // [기대] 늦은 쪽은 410(한 코드로 토큰 두 개가 나가지 않게).
    @Test
    @DisplayName("동시에 먼저 쓰인 코드(조건부 갱신 0건)는 410이다")
    void exchangeRace() {
        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("654321"),
                NOW.plus(FIVE_MIN), NOW);
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("654321"))).willReturn(Optional.of(code));
        given(codes.markUsed(any(), eq(NOW))).willReturn(0);
        assertThatThrownBy(() -> service.exchange("654321"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_EXPIRED);
    }

    // [상황] 기기 일련번호 없이 만든 예전 코드와, 일련번호가 있는 코드를 각각 넣는다.
    // [기대] 예전 코드는 400. 일련번호가 있으면 AGENT 토큰 안에 같은 일련번호가 들어간다
    //        (에이전트가 진단한 노트북과 렌탈 기기가 같은지 확인하는 데 쓴다).
    @Test
    @DisplayName("기기 시리얼 없이 만든 예전 코드는 400이고 시리얼이 있으면 AGENT 토큰에 같은 시리얼이 들어간다")
    void exchangeCarriesDeviceSerial() {
        PairingCode legacy = new PairingCode(NanoId.next(), NanoId.next(), null, Sha256.hex("777777"),
                NOW.plus(FIVE_MIN), NOW);
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("777777"))).willReturn(Optional.of(legacy));
        assertThatThrownBy(() -> service.exchange("777777"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_INVALID);

        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("888888"),
                NOW.plus(FIVE_MIN), NOW);
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("888888"))).willReturn(Optional.of(code));
        given(codes.markUsed(any(), eq(NOW))).willReturn(1);
        PairingService.AgentToken token = service.exchange("888888");
        assertThat(token.deviceSerial()).isEqualTo("C02TEST00001");
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.token().value().split("\\.")[1]),
                java.nio.charset.StandardCharsets.UTF_8);
        assertThat(payload).contains("\"deviceSerial\":\"C02TEST00001\"").contains("\"role\":\"AGENT\"");
    }

    // [상황] 틀린 코드를 넣고, 그다음 맞는 코드를 넣는다.
    // [기대] 틀린 코드는 "실패 1회"로 센다. 맞는 코드는 미리 잡아 둔 시도를 풀어 실패로 세지 않는다.
    @Test
    @DisplayName("틀린 코드는 잡은 시도를 확인된 실패로 바꾸고, 있는 코드는 같은 시도를 푼다")
    void wrongCodeCountsAsFailure() {
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("000000"))).willReturn(Optional.empty());
        assertThatThrownBy(() -> service.exchange("000000")).isInstanceOf(AuthException.class);
        verify(failures).recordFailure(ATTEMPT);
        verify(failures, never()).refund(any());

        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("888888"),
                NOW.plus(FIVE_MIN), NOW);
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("888888"))).willReturn(Optional.of(code));
        given(codes.markUsed(any(), eq(NOW))).willReturn(1);
        service.exchange("888888");
        verify(failures).refund(ATTEMPT);
    }

    // [상황] 틀린 코드가 몰려 전체 교환이 42초 동안 막힌 상태에서 맞는 코드를 넣는다.
    // [기대] 429와 남은 42초를 알리고, 코드를 조회하지도 쓰지도 않는다.
    @Test
    @DisplayName("전역 실패 한도로 막는 동안은 맞는 코드도 429와 남은 초로 거절하고 코드를 쓰지 않는다")
    void blockedExchangeIsRateLimited() {
        given(failures.tryAcquire()).willReturn(PairingFailureGuard.Attempt.rejected(42L));

        assertThatThrownBy(() -> service.exchange("888888"))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.code()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.retryAfterSeconds()).isEqualTo(42L);
                });
        verify(codes, never()).markUsed(any(), any());
        verify(codes, never()).findFirstByCodeHashOrderByCreatedAtDesc(any());
    }

    // [상황] 코드를 찾는 중 DB 오류가 난다.
    // [기대] 고객 잘못이 아니므로 실패로 세지 않고 시도를 풀고, 오류는 그대로 알린다.
    @Test
    @DisplayName("코드 조회가 예외를 던지면 잡아 둔 시도를 풀고 예외를 그대로 던진다")
    void lookupErrorReleasesAttempt() {
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(any())).willThrow(new IllegalStateException("db down"));
        assertThatThrownBy(() -> service.exchange("123123")).isInstanceOf(IllegalStateException.class);
        verify(failures).refund(ATTEMPT);
        verify(failures, never()).recordFailure(any());
    }
}
