package com.gakdo.trace.auth.pairing.infra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;

import com.gakdo.trace.auth.config.AuthProperties;

class RedisPairingFailureGuardTest {

    private static final Instant NOW = Instant.parse("2026-11-12T00:00:30Z");
    private static final String WINDOW_KEY = "trace:auth:pairing:fail:" + (NOW.toEpochMilli() / 60_000);
    private static final String BLOCK_KEY = "trace:auth:pairing:block";

    private final StringRedisTemplate redis = mock(StringRedisTemplate.class);
    @SuppressWarnings("unchecked")
    private final ValueOperations<String, String> values = mock(ValueOperations.class);
    private final AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://w",
            Duration.ofMinutes(15), Duration.ofDays(7), Duration.ofMinutes(30), Duration.ofHours(1),
            Duration.ofMinutes(10), Duration.ofMinutes(5), Duration.ofMinutes(30), true, null, null, null);
    private final RedisPairingFailureGuard guard =
            new RedisPairingFailureGuard(redis, Clock.fixed(NOW, ZoneOffset.UTC), properties);

    @Test
    @DisplayName("1분 창의 실패가 30번까지는 막지 않고, 31번째에 1분 동안 막는다")
    void blocksAfterThirtyFailuresInAMinute() {
        given(redis.opsForValue()).willReturn(values);
        given(values.increment(WINDOW_KEY)).willReturn(30L);
        guard.recordFailure();
        verify(values, never()).setIfAbsent(anyString(), anyString(), eq(Duration.ofMinutes(1)));

        given(values.increment(WINDOW_KEY)).willReturn(31L);
        guard.recordFailure();
        verify(values).setIfAbsent(BLOCK_KEY, "1", Duration.ofMinutes(1));
    }

    @Test
    @DisplayName("창의 첫 실패에만 2분 만료를 건다")
    void firstFailureSetsWindowExpiry() {
        given(redis.opsForValue()).willReturn(values);
        given(values.increment(WINDOW_KEY)).willReturn(1L);
        guard.recordFailure();
        verify(redis).expire(WINDOW_KEY, Duration.ofMinutes(2));
    }

    @Test
    @DisplayName("막는 키의 남은 초를 돌려주고, 키가 없으면 0이다")
    void reportsRemainingBlock() {
        given(redis.getExpire(BLOCK_KEY)).willReturn(-2L);
        assertThat(guard.blockedForSeconds()).isZero();
        given(redis.getExpire(BLOCK_KEY)).willReturn(17L);
        assertThat(guard.blockedForSeconds()).isEqualTo(17L);
    }

    @Test
    @DisplayName("Redis가 안 되면 막지 않고 교환을 계속한다")
    void failsOpenWhenRedisIsDown() {
        given(redis.getExpire(BLOCK_KEY)).willThrow(new RedisConnectionFailureException("down"));
        assertThat(guard.blockedForSeconds()).isZero();
        given(redis.opsForValue()).willThrow(new RedisConnectionFailureException("down"));
        guard.recordFailure();
    }
}
