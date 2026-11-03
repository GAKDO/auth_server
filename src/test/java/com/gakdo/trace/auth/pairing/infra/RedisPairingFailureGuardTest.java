package com.gakdo.trace.auth.pairing.infra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

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

class RedisPairingFailureGuardTest {

    private static final Instant NOW = Instant.parse("2026-11-12T00:00:30Z");
    private static final String WINDOW_KEY = "trace:auth:pairing:fail:" + (NOW.toEpochMilli() / 60_000);
    private static final String BLOCK_KEY = "trace:auth:pairing:block";

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), Duration.ofMinutes(5), Duration.ofMinutes(30), true, null, null, null);
    private final RedisPairingFailureGuard guard =
            new RedisPairingFailureGuard(redis, Clock.fixed(NOW, ZoneOffset.UTC), properties);

    @Test
    @DisplayName("확인·증가·막기를 스크립트 하나로 원자적으로 부르고 한도 30·창 2분·막기 60초를 넘긴다")
    void acquireRunsAtomicScript() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(0L);

        assertThat(guard.tryAcquire()).isZero();
        verify(redis).execute(RedisPairingFailureGuard.ACQUIRE, List.of(WINDOW_KEY, BLOCK_KEY), "30", "120000", "60");
    }

    @Test
    @DisplayName("스크립트가 남은 초를 돌려주면 그 초만큼 거절한다")
    void acquireReportsRemainingBlock() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class))).willReturn(17L);
        assertThat(guard.tryAcquire()).isEqualTo(17L);
    }

    @Test
    @DisplayName("스크립트는 막는 키를 먼저 보고, 31번째 시도에서 막는 키를 만든다")
    void scriptChecksBlockBeforeCounting() {
        String script = RedisPairingFailureGuard.ACQUIRE.getScriptAsString();
        assertThat(script.indexOf("PTTL")).isLessThan(script.indexOf("INCR"));
        assertThat(script).contains("n > tonumber(ARGV[1])").contains("'NX'");
    }

    @Test
    @DisplayName("있는 코드였던 시도는 창 키가 있을 때만 되돌린다")
    void refundDecrementsCurrentWindow() {
        guard.refund();
        verify(redis).execute(RedisPairingFailureGuard.REFUND, List.of(WINDOW_KEY));
        assertThat(RedisPairingFailureGuard.REFUND.getScriptAsString()).contains("EXISTS");
    }

    @Test
    @DisplayName("Redis가 안 되면 막지 않고 교환을 계속한다")
    void failsOpenWhenRedisIsDown() {
        given(redis.execute(eq(RedisPairingFailureGuard.ACQUIRE), anyList(), any(Object[].class)))
                .willThrow(new RedisConnectionFailureException("down"));
        assertThat(guard.tryAcquire()).isZero();
        given(redis.execute(eq(RedisPairingFailureGuard.REFUND), anyList(), any(Object[].class)))
                .willThrow(new RedisConnectionFailureException("down"));
        guard.refund();
    }
}
