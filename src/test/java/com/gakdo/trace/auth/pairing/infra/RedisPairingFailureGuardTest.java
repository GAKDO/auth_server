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

    private static final Instant NOW = Instant.parse("2026-11-12T00:00:59.900Z");
    private static final String WINDOW_KEY = "trace:auth:pairing:fail:" + (NOW.toEpochMilli() / 60_000);
    private static final String BLOCK_KEY = "trace:auth:pairing:block";

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), Duration.ofMinutes(5), Duration.ofMinutes(30), true, null, null, null);
    private final RedisPairingFailureGuard guard =
            new RedisPairingFailureGuard(redis, Clock.fixed(NOW, ZoneOffset.UTC), properties);

    // [상황] 교환을 시작하며 "시도 하나 잡기"를 한다(막힌 상태 아님).
    // [기대] Redis 스크립트 한 번으로 처리하고(한도 30·막는 시간 120초·창 60초), 잡은 1분 창 이름을 시도에 담는다.
    @Test
    @DisplayName("잡기는 스크립트 하나로 원자적으로 부르고, 받아들이면 잡은 창을 시도에 담는다")
    void acquireRunsAtomicScriptAndCarriesWindow() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(0L);

        Attempt attempt = guard.tryAcquire();

        assertThat(attempt.blockedForSeconds()).isZero();
        assertThat(attempt.window()).isEqualTo(WINDOW_KEY);
        verify(redis).execute(RedisPairingFailureGuard.ACQUIRE, List.of(WINDOW_KEY, BLOCK_KEY),
                "30", "120000", "60", "1");
    }

    // [상황] 이미 막힌 상태라 스크립트가 "17초 남음"을 돌려준다.
    // [기대] 17초 동안 거절한다.
    @Test
    @DisplayName("스크립트가 남은 초를 돌려주면 그 초만큼 거절한다")
    void acquireReportsRemainingBlock() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(17L);
        assertThat(guard.tryAcquire().blockedForSeconds()).isEqualTo(17L);
    }

    // [상황] 잡기 스크립트 내용을 본다.
    // [기대] 막힘 여부를 먼저 보고, "실패 + 지금 확인 중"이 한도면 막지 않고 미루기만 한다(막기는 시작하지 않음).
    @Test
    @DisplayName("잡기 스크립트는 막는 키를 먼저 보고, 실패+조회 중이 한도면 막지 않고 미루기만 한다")
    void acquireScriptNeverStartsBlock() {
        String script = RedisPairingFailureGuard.ACQUIRE.getScriptAsString();
        assertThat(script.indexOf("PTTL")).isLessThan(script.indexOf("HINCRBY"));
        assertThat(script).contains("f + p >= tonumber(ARGV[1])").doesNotContain("SET");
    }

    // [상황] 실패 기록 스크립트 내용을 본다.
    // [기대] 실제로 틀린 것으로 확인된 실패가 한도에 닿을 때만 막기를 시작한다.
    @Test
    @DisplayName("막기는 확인된 실패가 한도에 닿을 때만 실패 스크립트에서 시작한다")
    void onlyConfirmedFailuresStartBlock() {
        assertThat(RedisPairingFailureGuard.FAIL.getScriptAsString())
                .contains("'fail', 1").contains("f >= tonumber(ARGV[1])").contains("'NX'");
    }

    // [상황] 59.9초에 시도를 잡고, 다음 분으로 넘어간 뒤 실패·풀기를 기록한다.
    // [기대] 잡을 때의 1분 창에 기록한다(창이 바뀌어 숫자가 어긋나지 않게).
    @Test
    @DisplayName("분 경계를 넘어도 실패·풀기는 잡을 때의 창을 쓴다")
    void failureAndRefundUseAcquiredWindow() {
        Attempt attempt = Attempt.allowed("trace:auth:pairing:fail:old");

        guard.recordFailure(attempt);
        guard.refund(attempt);

        verify(redis).execute(RedisPairingFailureGuard.FAIL, List.of("trace:auth:pairing:fail:old", BLOCK_KEY),
                "30", "60");
        verify(redis).execute(RedisPairingFailureGuard.REFUND, List.of("trace:auth:pairing:fail:old"));
    }

    // [상황] Redis가 고장 났다.
    // [기대] 서비스를 멈추지 않고 교환을 계속 허용한다. 창 없는 시도는 나중에 Redis를 부르지도 않는다.
    @Test
    @DisplayName("Redis가 안 되면 막지 않고 교환을 계속하고, 창 없는 시도는 Redis를 부르지 않는다")
    void failsOpenWhenRedisIsDown() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class)))
                .willThrow(new RedisConnectionFailureException("down"));
        Attempt attempt = guard.tryAcquire();
        assertThat(attempt.blockedForSeconds()).isZero();
        assertThat(attempt.window()).isNull();

        StringRedisTemplate untouched = mock(StringRedisTemplate.class);
        RedisPairingFailureGuard other =
                new RedisPairingFailureGuard(untouched, Clock.fixed(NOW, ZoneOffset.UTC), properties);
        other.recordFailure(attempt);
        other.refund(attempt);
        verifyNoInteractions(untouched);
    }
}
