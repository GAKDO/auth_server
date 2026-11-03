package com.gakdo.trace.auth.pairing.infra;

import java.time.Clock;
import java.time.Duration;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.pairing.application.PairingFailureGuard;

/**
 * 분 단위 고정 창으로 실패를 센다: trace:auth:pairing:fail:{분}(INCR, 2분 뒤 사라짐).
 * 한 창에서 30번을 넘으면 trace:auth:pairing:block을 1분 걸어 맞는 코드까지 모두 429로 막는다.
 * Redis가 안 되면 막지 않고(로그만) 교환을 계속한다. gateway의 IP당 제한은 그대로 남는다.
 */
@Component
public class RedisPairingFailureGuard implements PairingFailureGuard {

    static final int MAX_FAILURES_PER_MINUTE = 30;
    static final Duration BLOCK = Duration.ofMinutes(1);

    private static final Logger log = LoggerFactory.getLogger(RedisPairingFailureGuard.class);
    private static final Duration WINDOW_TTL = Duration.ofMinutes(2);

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final String prefix;

    public RedisPairingFailureGuard(StringRedisTemplate redis, Clock clock, AuthProperties properties) {
        this.redis = redis;
        this.clock = clock;
        this.prefix = properties.redisKeyPrefix() + "auth:pairing:";
    }

    @Override
    public long blockedForSeconds() {
        try {
            Long ttl = redis.getExpire(prefix + "block");
            // -2: 키 없음, -1: 만료 없음(만들 때 항상 만료를 거니 생기지 않지만 막는 쪽으로 본다)
            if (ttl == null || ttl == -2) {
                return 0;
            }
            return ttl < 0 ? BLOCK.toSeconds() : Math.max(ttl, 1);
        } catch (DataAccessException e) {
            log.warn("페어링 실패 한도를 읽지 못해 막지 않고 진행합니다: {}", e.getMessage());
            return 0;
        }
    }

    @Override
    public void recordFailure() {
        try {
            String windowKey = prefix + "fail:" + (clock.millis() / 60_000);
            Long count = redis.opsForValue().increment(windowKey);
            if (count != null && count == 1) {
                redis.expire(windowKey, WINDOW_TTL);
            }
            if (count != null && count > MAX_FAILURES_PER_MINUTE) {
                Boolean started = redis.opsForValue().setIfAbsent(prefix + "block", "1", BLOCK);
                if (Boolean.TRUE.equals(started)) {
                    log.warn("페어링 코드 실패가 1분에 {}번을 넘어 {}초 동안 교환을 막습니다", MAX_FAILURES_PER_MINUTE,
                            BLOCK.toSeconds());
                }
            }
        } catch (DataAccessException e) {
            log.warn("페어링 실패를 세지 못했습니다: {}", e.getMessage());
        }
    }
}
