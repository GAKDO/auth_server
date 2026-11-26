// 이 파일이 확인하는 것: 페어링 코드 무차별 대입 막기(Redis로 1분마다 실패를 센다).
// 1분에 틀린 코드가 30번 쌓이면 2분 동안 모든 페어링 교환을 막는다. 가짜 Redis로 보낸 명령을 확인한다.

package com.gakdo.trace.auth.pairing.infra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.pairing.application.PairingFailureGuard.Attempt;

class RedisPairingFailureGuardTest {

    // 시험 속 "지금"을 1분이 끝나기 직전(59.9초)으로 고정한다 = 분 경계 문제를 시험하려고
    private static final Instant NOW = Instant.parse("2026-11-12T00:00:59.900Z");
    // 지금 시각이 속한 1분 창의 Redis 열쇠 이름(분 번호를 붙임)
    private static final String WINDOW_KEY = "trace:auth:pairing:fail:" + (NOW.toEpochMilli() / 60_000);
    // "페어링 막힘" 표시를 담는 Redis 열쇠 이름
    private static final String BLOCK_KEY = "trace:auth:pairing:block";

    // (도구) mock(종류) = 진짜 대신 가짜 객체를 만든다. 진짜 Redis 없이 어떤 명령을 보냈는지만 보려고
    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    // Redis 접두사 trace: 등을 넣은 인증 설정(유효 시간들은 시험과 상관없음)
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), Duration.ofMinutes(5), Duration.ofMinutes(30), true, null, null, null);
    // 시험할 실패 막기 도구를 가짜 Redis·고정 시계·설정으로 만든다
    private final RedisPairingFailureGuard guard =
            new RedisPairingFailureGuard(redis, Clock.fixed(NOW, ZoneOffset.UTC), properties);

    // [상황] 교환을 시작하며 "시도 하나 잡기"를 한다(막힌 상태 아님).
    // [기대] Redis 스크립트 한 번으로 처리하고(한도 30·막는 시간 120초·창 60초), 잡은 1분 창 이름을 시도에 담는다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("잡기는 스크립트 하나로 원자적으로 부르고, 받아들이면 잡은 창을 시도에 담는다")
    void acquireRunsAtomicScriptAndCarriesWindow() {
        // (도구) given(가짜.메서드(조건)).willReturn(결과) = when().thenReturn()과 같은 뜻. "이 호출이 오면 이 값을 돌려줘". eq = 그 값일 때, anyList()·any = 아무 값이나
        // 준비: 잡기 스크립트를 실행하면 0(막힘 아님)을 돌려주게 한다
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(0L);

        // 실행: 페어링 시도 하나를 잡는다
        Attempt attempt = guard.tryAcquire();

        // (도구) assertThat(값).isZero() = 값이 0이어야 통과하는 AssertJ 검사
        // 확인: 막힌 시간이 0초여야 한다 = 받아들임
        assertThat(attempt.blockedForSeconds()).isZero();
        // (도구) isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 시도에 지금 1분 창 이름이 담겨야 한다
        assertThat(attempt.window()).isEqualTo(WINDOW_KEY);
        // (도구) verify(가짜).메서드(값...) = 가짜의 그 메서드가 정확히 그 값들로 (한 번) 불렸는지 확인
        // 확인: 잡기 스크립트를 창·막힘 열쇠와 한도 30·막는 시간 120000ms·창 60초·1로 한 번에 불렀어야 한다 = 원자적으로 처리
        verify(redis).execute(RedisPairingFailureGuard.ACQUIRE, List.of(WINDOW_KEY, BLOCK_KEY),
                "30", "120000", "60", "1");
    }

    // [상황] 이미 막힌 상태라 스크립트가 "17초 남음"을 돌려준다.
    // [기대] 17초 동안 거절한다.
    @Test
    @DisplayName("스크립트가 남은 초를 돌려주면 그 초만큼 거절한다")
    void acquireReportsRemainingBlock() {
        // 준비: 잡기 스크립트가 17(남은 막힘 초)을 돌려주게 한다
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(17L);
        // 실행+확인: 시도를 잡으면 17초 동안 막혀 있다고 나와야 한다
        assertThat(guard.tryAcquire().blockedForSeconds()).isEqualTo(17L);
    }

    // [상황] 잡기 스크립트 내용을 본다.
    // [기대] 막힘 여부를 먼저 보고, "실패 + 지금 확인 중"이 한도면 막지 않고 미루기만 한다(막기는 시작하지 않음).
    @Test
    @DisplayName("잡기 스크립트는 막는 키를 먼저 보고, 실패+조회 중이 한도면 막지 않고 미루기만 한다")
    void acquireScriptNeverStartsBlock() {
        // 준비: 잡기 스크립트(Lua) 글자를 꺼낸다
        String script = RedisPairingFailureGuard.ACQUIRE.getScriptAsString();
        // (도구) isLessThan(값) = 값보다 작아야 통과
        // 확인: 막힘 남은 시간 확인(PTTL)이 숫자 올리기(HINCRBY)보다 먼저 나와야 한다 = 막힘부터 본다
        assertThat(script.indexOf("PTTL")).isLessThan(script.indexOf("HINCRBY"));
        // (도구) contains(글자) = 그 글자가 있어야, doesNotContain(글자) = 없어야 통과
        // 확인: "실패 + 확인 중"이 한도면 미루는 조건이 있고, 막기를 시작하는 SET 명령은 없어야 한다
        assertThat(script).contains("f + p >= tonumber(ARGV[1])").doesNotContain("SET");
    }

    // [상황] 실패 기록 스크립트 내용을 본다.
    // [기대] 실제로 틀린 것으로 확인된 실패가 한도에 닿을 때만 막기를 시작한다.
    @Test
    @DisplayName("막기는 확인된 실패가 한도에 닿을 때만 실패 스크립트에서 시작한다")
    void onlyConfirmedFailuresStartBlock() {
        // 실행+확인: 실패 기록 스크립트 글자에
        assertThat(RedisPairingFailureGuard.FAIL.getScriptAsString())
                // 실패 1 올리기, 확인된 실패가 한도에 닿았는지 보기, 막힘이 없을 때만 막기(NX)가 모두 있어야 한다
                .contains("'fail', 1").contains("f >= tonumber(ARGV[1])").contains("'NX'");
    }

    // [상황] 59.9초에 시도를 잡고, 다음 분으로 넘어간 뒤 실패·풀기를 기록한다.
    // [기대] 잡을 때의 1분 창에 기록한다(창이 바뀌어 숫자가 어긋나지 않게).
    @Test
    @DisplayName("분 경계를 넘어도 실패·풀기는 잡을 때의 창을 쓴다")
    void failureAndRefundUseAcquiredWindow() {
        // 준비: 이전 분 창("old")에서 잡은 시도를 만든다(그 사이 분이 바뀐 상황)
        Attempt attempt = Attempt.allowed("trace:auth:pairing:fail:old");

        // 실행: 그 시도의 실패를 기록한다
        guard.recordFailure(attempt);
        // 실행: 그 시도를 풀어 준다(확인 중 숫자 되돌리기)
        guard.refund(attempt);

        // 확인: 실패 기록이 지금 창이 아니라 잡을 때의 "old" 창에 들어갔어야 한다
        verify(redis).execute(RedisPairingFailureGuard.FAIL, List.of("trace:auth:pairing:fail:old", BLOCK_KEY),
                "30", "60");
        // 확인: 풀기도 "old" 창에 했어야 한다 = 창이 바뀌어도 숫자가 어긋나지 않는다
        verify(redis).execute(RedisPairingFailureGuard.REFUND, List.of("trace:auth:pairing:fail:old"));
    }

    // [상황] Redis가 고장 났다.
    // [기대] 서비스를 멈추지 않고 교환을 계속 허용한다. 창 없는 시도는 나중에 Redis를 부르지도 않는다.
    @Test
    @DisplayName("Redis가 안 되면 막지 않고 교환을 계속하고, 창 없는 시도는 Redis를 부르지 않는다")
    void failsOpenWhenRedisIsDown() {
        // (도구) willThrow(예외) = 그 호출이 오면 예외를 던지게 한다
        // 준비: 잡기 스크립트를 부르면 "Redis 연결 실패" 예외가 나게 한다 = Redis 고장
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class)))
                .willThrow(new RedisConnectionFailureException("down"));
        // 실행: 시도를 잡는다
        Attempt attempt = guard.tryAcquire();
        // 확인: 막지 않고 받아들여야 한다 = Redis 때문에 페어링이 멈추지 않게
        assertThat(attempt.blockedForSeconds()).isZero();
        // (도구) isNull() = 값이 없어야 통과
        // 확인: 잡은 창이 없어야 한다
        assertThat(attempt.window()).isNull();

        // 준비: 한 번도 쓰이면 안 되는 새 가짜 Redis를 만든다
        StringRedisTemplate untouched = mock(StringRedisTemplate.class);
        // 그 가짜 Redis로 다른 실패 막기 도구를 만든다
        RedisPairingFailureGuard other =
                new RedisPairingFailureGuard(untouched, Clock.fixed(NOW, ZoneOffset.UTC), properties);
        // 실행: 창 없는 시도로 실패를 기록한다
        other.recordFailure(attempt);
        // 실행: 창 없는 시도를 풀어 준다
        other.refund(attempt);
        // (도구) verifyNoInteractions(가짜) = 그 가짜가 한 번도 불리지 않았는지 확인
        // 확인: 창 없는 시도는 Redis를 아예 부르지 않았어야 한다
        verifyNoInteractions(untouched);
    }
}
