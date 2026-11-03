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

    @Test
    @DisplayName("페어링 코드는 5분 뒤 만료되고 같은 값의 유효한 코드가 있으면 다시 뽑는다")
    void createRedrawsCollision() {
        given(tokens.sixDigitCode()).willReturn("111111", "222222");
        given(codes.existsByCodeHashAndUsedAtIsNullAndExpiresAtAfter(Sha256.hex("111111"), NOW)).willReturn(true);

        PairingService.IssuedCode issued = service.create(NanoId.next(), NanoId.next(), "C02TEST00001");

        assertThat(issued.code()).isEqualTo("222222");
        assertThat(issued.expiresAt()).isEqualTo(NOW.plus(FIVE_MIN));
    }

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

    @Test
    @DisplayName("틀린 코드는 전역 실패 한도에 한 번 센다")
    void wrongCodeCountsAsFailure() {
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("000000"))).willReturn(Optional.empty());
        assertThatThrownBy(() -> service.exchange("000000")).isInstanceOf(AuthException.class);
        verify(failures).recordFailure();
    }

    @Test
    @DisplayName("전역 실패 한도로 막는 동안은 맞는 코드도 429와 남은 초로 거절하고 코드를 쓰지 않는다")
    void blockedExchangeIsRateLimited() {
        given(failures.blockedForSeconds()).willReturn(42L);

        assertThatThrownBy(() -> service.exchange("888888"))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    assertThat(e.code()).isEqualTo(ErrorCode.RATE_LIMITED);
                    assertThat(e.retryAfterSeconds()).isEqualTo(42L);
                });
        verify(codes, never()).markUsed(any(), any());
    }
}
