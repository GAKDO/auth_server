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

    // 시험 속 "지금" 시각을 고정한다
    private static final Instant NOW = Instant.parse("2026-11-12T00:00:00Z");
    // 페어링 코드 유효 시간 5분
    private static final Duration FIVE_MIN = Duration.ofMinutes(5);

    // (도구) mock(종류) = 진짜 대신 가짜 객체를 만든다. DB 없이 돌리려고 코드 저장소를 가짜로 둔다
    private final PairingCodeRepository codes = mock(PairingCodeRepository.class);
    // 무작위 코드 만들기 도구(가짜). 어떤 숫자를 뽑을지 정해 두려고
    private final SecureTokens tokens = mock(SecureTokens.class);
    // 항상 NOW를 가리키는 고정 시계
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);
    // 페어링 코드 유효 시간을 5분으로 둔 인증 설정
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), FIVE_MIN, Duration.ofMinutes(30), true, null, null, null);
    // 틀린 코드 몰림 막기 도구(가짜). 실패를 셌는지 확인하려고
    private final PairingFailureGuard failures = mock(PairingFailureGuard.class);
    // 시험할 페어링 서비스. 토큰 발급기(JwtIssuer)는 진짜를 써서 실제 AGENT 토큰을 만든다
    private final PairingService service = new PairingService(codes, tokens,
            new JwtIssuer(new SigningKeyProvider(properties), properties, clock), properties, clock, failures);
    // "받아들임" 상태로 잡힌 시도 하나(창 이름 w)
    private static final PairingFailureGuard.Attempt ATTEMPT = PairingFailureGuard.Attempt.allowed("w");

    {
        // (도구) given(가짜.메서드()).willReturn(결과) = when().thenReturn()과 같은 뜻. "이 호출이 오면 이 값을 돌려줘"
        // 모든 테스트 공통 준비: 시도를 잡으면 기본으로 받아들인 시도를 돌려주게 한다
        given(failures.tryAcquire()).willReturn(ATTEMPT);
    }

    // [상황] 새 코드를 뽑았는데 같은 숫자(111111)의 유효한 코드가 이미 있다.
    // [기대] 다시 뽑아 222222를 주고, 만료는 5분 뒤다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("페어링 코드는 5분 뒤 만료되고 같은 값의 유효한 코드가 있으면 다시 뽑는다")
    void createRedrawsCollision() {
        // 준비: 코드를 뽑으면 처음엔 111111, 다음엔 222222가 나오게 한다
        given(tokens.sixDigitCode()).willReturn("111111", "222222");
        // 준비: 111111은 이미 유효한 코드가 있다고 답하게 한다(겹침)
        given(codes.existsByCodeHashAndUsedAtIsNullAndExpiresAtAfter(Sha256.hex("111111"), NOW)).willReturn(true);

        // 실행: 렌탈·시점·기기 일련번호로 페어링 코드를 발급한다
        PairingService.IssuedCode issued = service.create(NanoId.next(), NanoId.next(), "C02TEST00001");

        // (도구) assertThat(값).isEqualTo(기대값) = "값이 기대값과 같아야 한다"를 확인하는 AssertJ 도구
        // 확인: 겹친 111111을 버리고 다시 뽑은 222222를 줘야 한다
        assertThat(issued.code()).isEqualTo("222222");
        // 확인: 만료 시각이 지금부터 5분 뒤여야 한다
        assertThat(issued.expiresAt()).isEqualTo(NOW.plus(FIVE_MIN));
    }

    // [상황] 없는 코드를 넣고, 만료된 코드를 넣는다.
    // [기대] 없으면 400 PAIRING_CODE_INVALID, 만료면 410 PAIRING_CODE_EXPIRED.
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음, 410 = 이미 쓰였거나 만료되어 더는 쓸 수 없음
    @Test
    @DisplayName("없는 코드는 400, 만료된 코드는 410이다")
    void exchangeFailures() {
        // (도구) any() = 아무 값이나. Optional.empty() = "없음"
        // 준비: 어떤 코드를 찾아도 없다고 답하게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(any())).willReturn(Optional.empty());
        // (도구) assertThatThrownBy(() -> 코드) = 그 코드를 돌리면 예외가 나야 통과. extracting = 예외에서 값을 꺼내 검사
        // 실행+확인: 없는 코드(000000)로 교환하면
        assertThatThrownBy(() -> service.exchange("000000"))
                // 오류 코드가 PAIRING_CODE_INVALID(400)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_INVALID);

        // 준비: 1초 전에 만료된 코드(123456)를 만든다
        PairingCode expired = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("123456"),
                NOW.minusSeconds(1), NOW.minus(FIVE_MIN));
        // 준비: 123456의 해시로 찾으면 그 만료된 코드를 돌려주게 한다(DB에는 해시만 저장)
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("123456"))).willReturn(Optional.of(expired));
        // 실행+확인: 만료된 코드로 교환하면
        assertThatThrownBy(() -> service.exchange("123456"))
                // 오류 코드가 PAIRING_CODE_EXPIRED(410)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_EXPIRED);
    }

    // [상황] 같은 코드를 두 곳에서 동시에 넣어 다른 쪽이 먼저 썼다.
    // [기대] 늦은 쪽은 410(한 코드로 토큰 두 개가 나가지 않게).
    //        ※ 응답 코드: 410 = 이미 쓰였거나 만료되어 더는 쓸 수 없음
    @Test
    @DisplayName("동시에 먼저 쓰인 코드(조건부 갱신 0건)는 410이다")
    void exchangeRace() {
        // 준비: 아직 유효한 코드(654321)를 만든다
        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("654321"),
                NOW.plus(FIVE_MIN), NOW);
        // 준비: 그 코드를 찾으면 돌려주게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("654321"))).willReturn(Optional.of(code));
        // (도구) eq(값) = 그 값일 때만
        // 준비: "아직 안 쓴 코드만 쓴 것으로 바꾸기"가 0건이라고 답하게 한다 = 다른 쪽이 먼저 씀
        given(codes.markUsed(any(), eq(NOW))).willReturn(0);
        // 실행+확인: 그 코드로 교환하면
        assertThatThrownBy(() -> service.exchange("654321"))
                // 410(이미 쓰임)이어야 한다 = 한 코드로 토큰이 두 개 나가지 않는다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_EXPIRED);
    }

    // [상황] 기기 일련번호 없이 만든 예전 코드와, 일련번호가 있는 코드를 각각 넣는다.
    // [기대] 예전 코드는 400. 일련번호가 있으면 AGENT 토큰 안에 같은 일련번호가 들어간다
    //        (에이전트가 진단한 노트북과 렌탈 기기가 같은지 확인하는 데 쓴다).
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음
    @Test
    @DisplayName("기기 시리얼 없이 만든 예전 코드는 400이고 시리얼이 있으면 AGENT 토큰에 같은 시리얼이 들어간다")
    void exchangeCarriesDeviceSerial() {
        // 준비: 기기 일련번호 없이(null) 만든 예전 코드(777777)를 만든다
        PairingCode legacy = new PairingCode(NanoId.next(), NanoId.next(), null, Sha256.hex("777777"),
                NOW.plus(FIVE_MIN), NOW);
        // 준비: 그 코드를 찾으면 돌려주게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("777777"))).willReturn(Optional.of(legacy));
        // 실행+확인: 예전 코드로 교환하면
        assertThatThrownBy(() -> service.exchange("777777"))
                // 400(쓸 수 없는 코드)이어야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.PAIRING_CODE_INVALID);

        // 준비: 일련번호 C02TEST00001이 묶인 유효한 코드(888888)를 만든다
        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("888888"),
                NOW.plus(FIVE_MIN), NOW);
        // 준비: 그 코드를 찾으면 돌려주게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("888888"))).willReturn(Optional.of(code));
        // 준비: 쓴 것으로 바꾸기가 1건 성공했다고 답하게 한다
        given(codes.markUsed(any(), eq(NOW))).willReturn(1);
        // 실행: 그 코드를 AGENT 토큰으로 바꾼다
        PairingService.AgentToken token = service.exchange("888888");
        // 확인: 결과에 같은 기기 일련번호가 있어야 한다
        assertThat(token.deviceSerial()).isEqualTo("C02TEST00001");
        // 토큰(JWT)의 가운데 조각(내용)을 base64로 풀어 글자로 읽는다
        String payload = new String(java.util.Base64.getUrlDecoder().decode(token.token().value().split("\\.")[1]),
                java.nio.charset.StandardCharsets.UTF_8);
        // (도구) contains(글자) = 그 글자가 들어 있어야 통과
        // 확인: 토큰 안에 일련번호와 역할 AGENT가 들어 있어야 한다 = 진단한 노트북이 렌탈 기기인지 확인할 수 있다
        assertThat(payload).contains("\"deviceSerial\":\"C02TEST00001\"").contains("\"role\":\"AGENT\"");
    }

    // [상황] 틀린 코드를 넣고, 그다음 맞는 코드를 넣는다.
    // [기대] 틀린 코드는 "실패 1회"로 센다. 맞는 코드는 미리 잡아 둔 시도를 풀어 실패로 세지 않는다.
    @Test
    @DisplayName("틀린 코드는 잡은 시도를 확인된 실패로 바꾸고, 있는 코드는 같은 시도를 푼다")
    void wrongCodeCountsAsFailure() {
        // 준비: 000000은 없는 코드라고 답하게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("000000"))).willReturn(Optional.empty());
        // (도구) isInstanceOf(종류) = 그 종류의 예외여야 통과
        // 실행+확인: 틀린 코드로 교환하면 인증 예외가 나야 한다
        assertThatThrownBy(() -> service.exchange("000000")).isInstanceOf(AuthException.class);
        // (도구) verify(가짜).메서드(값) = 가짜의 그 메서드가 그 값으로 (한 번) 불렸는지 확인
        // 확인: 잡아 둔 시도를 "확인된 실패"로 기록했어야 한다
        verify(failures).recordFailure(ATTEMPT);
        // (도구) never() = 한 번도 불리지 않았어야 통과
        // 확인: 실패한 시도는 풀어 주지 않았어야 한다
        verify(failures, never()).refund(any());

        // 준비: 유효한 코드(888888)를 만든다
        PairingCode code = new PairingCode(NanoId.next(), NanoId.next(), "C02TEST00001", Sha256.hex("888888"),
                NOW.plus(FIVE_MIN), NOW);
        // 준비: 그 코드를 찾으면 돌려주게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex("888888"))).willReturn(Optional.of(code));
        // 준비: 쓴 것으로 바꾸기가 성공하게 한다
        given(codes.markUsed(any(), eq(NOW))).willReturn(1);
        // 실행: 맞는 코드로 교환한다
        service.exchange("888888");
        // 확인: 같은 시도를 풀어 줬어야 한다 = 맞는 코드는 실패로 세지 않는다
        verify(failures).refund(ATTEMPT);
    }

    // [상황] 틀린 코드가 몰려 전체 교환이 42초 동안 막힌 상태에서 맞는 코드를 넣는다.
    // [기대] 429와 남은 42초를 알리고, 코드를 조회하지도 쓰지도 않는다.
    //        ※ 응답 코드: 429 = 요청이 너무 잦아 잠시 막음
    @Test
    @DisplayName("전역 실패 한도로 막는 동안은 맞는 코드도 429와 남은 초로 거절하고 코드를 쓰지 않는다")
    void blockedExchangeIsRateLimited() {
        // 준비: 시도를 잡으면 "42초 동안 막힘"을 돌려주게 한다
        given(failures.tryAcquire()).willReturn(PairingFailureGuard.Attempt.rejected(42L));

        // (도구) isInstanceOfSatisfying(종류, e -> {...}) = 그 종류의 예외이고 안의 검사도 통과해야 한다
        // 실행+확인: 맞는 코드로 교환해도
        assertThatThrownBy(() -> service.exchange("888888"))
                .isInstanceOfSatisfying(RateLimitedException.class, e -> {
                    // 오류 코드가 RATE_LIMITED(429, 너무 잦음)여야 하고
                    assertThat(e.code()).isEqualTo(ErrorCode.RATE_LIMITED);
                    // 다시 시도까지 남은 시간이 42초여야 한다
                    assertThat(e.retryAfterSeconds()).isEqualTo(42L);
                });
        // 확인: 코드를 쓴 것으로 바꾸지 않았어야 한다
        verify(codes, never()).markUsed(any(), any());
        // 확인: 코드를 조회하지도 않았어야 한다 = 막힌 동안은 맞히기 시도 자체를 못 한다
        verify(codes, never()).findFirstByCodeHashOrderByCreatedAtDesc(any());
    }

    // [상황] 코드를 찾는 중 DB 오류가 난다.
    // [기대] 고객 잘못이 아니므로 실패로 세지 않고 시도를 풀고, 오류는 그대로 알린다.
    @Test
    @DisplayName("코드 조회가 예외를 던지면 잡아 둔 시도를 풀고 예외를 그대로 던진다")
    void lookupErrorReleasesAttempt() {
        // (도구) willThrow(예외) = 그 호출이 오면 예외를 던지게 한다
        // 준비: 코드를 찾으면 DB 오류 예외가 나게 한다
        given(codes.findFirstByCodeHashOrderByCreatedAtDesc(any())).willThrow(new IllegalStateException("db down"));
        // 실행+확인: 교환하면 그 DB 오류가 그대로 나와야 한다
        assertThatThrownBy(() -> service.exchange("123123")).isInstanceOf(IllegalStateException.class);
        // 확인: 잡아 둔 시도를 풀어 줬어야 한다
        verify(failures).refund(ATTEMPT);
        // 확인: 고객 잘못이 아니니 실패로 세지 않았어야 한다
        verify(failures, never()).recordFailure(any());
    }
}
