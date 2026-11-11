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

    @Test
    @DisplayName("스크립트가 남은 초를 돌려주면 그 초만큼 거절한다")
    void acquireReportsRemainingBlock() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(17L);
        assertThat(guard.tryAcquire().blockedForSeconds()).isEqualTo(17L);
    }

    @Test
    @DisplayName("잡기 스크립트는 막는 키를 먼저 보고, 실패+조회 중이 한도면 막지 않고 미루기만 한다")
    void acquireScriptNeverStartsBlock() {
        String script = RedisPairingFailureGuard.ACQUIRE.getScriptAsString();
        assertThat(script.indexOf("PTTL")).isLessThan(script.indexOf("HINCRBY"));
        assertThat(script).contains("f + p >= tonumber(ARGV[1])").doesNotContain("SET");
    }

    @Test
    @DisplayName("막기는 확인된 실패가 한도에 닿을 때만 실패 스크립트에서 시작한다")
    void onlyConfirmedFailuresStartBlock() {
        assertThat(RedisPairingFailureGuard.FAIL.getScriptAsString())
                .contains("'fail', 1").contains("f >= tonumber(ARGV[1])").contains("'NX'");
    }

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
