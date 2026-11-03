package com.gakdo.trace.auth.pairing.infra;

import java.time.Clock;
import java.time.Duration;
import java.util.List;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.pairing.application.PairingFailureGuard;

/**
 * 분 단위 고정 창으로 시도를 센다: trace:auth:pairing:fail:{분}(2분 뒤 사라짐).
 * 조회 전에 Lua 스크립트 하나로 "막는 중인지 확인 → 창 수 증가 → 30을 넘으면 trace:auth:pairing:block을 1분"을
 * 원자적으로 처리해, 동시 요청이 한꺼번에 확인을 통과해 한도를 넘는 경합을 없앤다. 코드가 있던 시도는 되돌린다.
 * Redis가 안 되면 막지 않고(로그만) 교환을 계속한다. gateway의 IP당 제한은 그대로 남는다.
 */
@Component
public class RedisPairingFailureGuard implements PairingFailureGuard {

    static final int MAX_FAILURES_PER_MINUTE = 30;
    static final Duration BLOCK = Duration.ofMinutes(1);
    static final Duration WINDOW_TTL = Duration.ofMinutes(2);

    /** KEYS[1]=창 키, KEYS[2]=막는 키. ARGV[1]=한도, ARGV[2]=창 만료(ms), ARGV[3]=막는 시간(s). 받아들이면 0, 아니면 남은 초. */
    static final RedisScript<Long> ACQUIRE = new DefaultRedisScript<>("""
            local ttl = redis.call('PTTL', KEYS[2])
            if ttl > 0 then return math.ceil(ttl / 1000) end
            if ttl == -1 then return tonumber(ARGV[3]) end
            local n = redis.call('INCR', KEYS[1])
            if n == 1 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
            if n > tonumber(ARGV[1]) then
              redis.call('SET', KEYS[2], '1', 'EX', ARGV[3], 'NX')
              return tonumber(ARGV[3])
            end
            return 0
            """, Long.class);

    /** 창 키가 있을 때만 줄인다(없는 키를 DECR하면 만료 없는 -1이 남는다). */
    static final RedisScript<Long> REFUND = new DefaultRedisScript<>("""
            if redis.call('EXISTS', KEYS[1]) == 1 then return redis.call('DECR', KEYS[1]) end
            return 0
            """, Long.class);

    private static final Logger log = LoggerFactory.getLogger(RedisPairingFailureGuard.class);

    private final StringRedisTemplate redis;
    private final Clock clock;
    private final String prefix;

    public RedisPairingFailureGuard(StringRedisTemplate redis, Clock clock, AuthProperties properties) {
        this.redis = redis;
        this.clock = clock;
        this.prefix = properties.redisKeyPrefix() + "auth:pairing:";
    }

    @Override
    public long tryAcquire() {
        try {
            Long blocked = redis.execute(ACQUIRE, List.of(windowKey(), prefix + "block"),
                    String.valueOf(MAX_FAILURES_PER_MINUTE), String.valueOf(WINDOW_TTL.toMillis()),
                    String.valueOf(BLOCK.toSeconds()));
            if (blocked == null || blocked <= 0) {
                return 0;
            }
            log.warn("페어링 코드 시도가 1분에 {}번을 넘어 교환을 막는 중입니다(남은 {}초)", MAX_FAILURES_PER_MINUTE, blocked);
            return blocked;
        } catch (DataAccessException e) {
            log.warn("페어링 실패 한도를 확인하지 못해 막지 않고 진행합니다: {}", e.getMessage());
            return 0;
        }
    }

    @Override
    public void refund() {
        try {
            redis.execute(REFUND, List.of(windowKey()));
        } catch (DataAccessException e) {
            log.warn("페어링 시도를 되돌리지 못했습니다: {}", e.getMessage());
        }
    }

    private String windowKey() {
        return prefix + "fail:" + (clock.millis() / 60_000);
    }
}
