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
 * 분 단위 고정 창 해시 trace:auth:pairing:fail:{분}(필드 fail=확인된 실패, pending=조회 중, 2분 뒤 사라짐).
 * 세 Lua 스크립트로 확인·증가를 원자적으로 처리한다.
 * <ul>
 * <li>잡기: 막는 중이면 남은 초. fail + pending이 30에 닿았으면 1초 뒤 다시(막지는 않음). 아니면 pending + 1.</li>
 * <li>실패: pending − 1, fail + 1, fail이 30에 닿으면 trace:auth:pairing:block을 1분.</li>
 * <li>풀기: pending − 1.</li>
 * </ul>
 * 그래서 한 창에서 조회되는 틀린 코드는 동시 요청이어도 30개를 넘지 못하고, 맞는 코드의 동시 요청만으로는 막지 않는다.
 * Redis가 안 되면 막지 않고(로그만) 교환을 계속한다. gateway의 IP당 제한은 그대로 남는다.
 */
@Component
public class RedisPairingFailureGuard implements PairingFailureGuard {

    static final int MAX_FAILURES_PER_MINUTE = 30;
    static final Duration BLOCK = Duration.ofMinutes(1);
    static final Duration WINDOW_TTL = Duration.ofMinutes(2);
    /** 조회 중인 시도가 한도를 채웠을 때 다시 해 볼 때까지(막는 것이 아니라 잠깐 미루는 것). */
    static final long BUSY_RETRY_SECONDS = 1;

    /** KEYS[1]=창, KEYS[2]=막는 키. ARGV[1]=한도, ARGV[2]=창 만료(ms), ARGV[3]=막는 시간(s), ARGV[4]=다시 해 볼 초. */
    static final RedisScript<Long> ACQUIRE = new DefaultRedisScript<>("""
            local ttl = redis.call('PTTL', KEYS[2])
            if ttl > 0 then return math.ceil(ttl / 1000) end
            if ttl == -1 then return tonumber(ARGV[3]) end
            local f = tonumber(redis.call('HGET', KEYS[1], 'fail') or '0')
            local p = tonumber(redis.call('HGET', KEYS[1], 'pending') or '0')
            if f + p >= tonumber(ARGV[1]) then return tonumber(ARGV[4]) end
            redis.call('HINCRBY', KEYS[1], 'pending', 1)
            if redis.call('PTTL', KEYS[1]) < 0 then redis.call('PEXPIRE', KEYS[1], ARGV[2]) end
            return 0
            """, Long.class);

    /** KEYS[1]=창, KEYS[2]=막는 키. ARGV[1]=한도, ARGV[2]=막는 시간(s). 막기를 시작하면 1. */
    static final RedisScript<Long> FAIL = new DefaultRedisScript<>("""
            if redis.call('EXISTS', KEYS[1]) == 0 then return 0 end
            if tonumber(redis.call('HGET', KEYS[1], 'pending') or '0') > 0 then
              redis.call('HINCRBY', KEYS[1], 'pending', -1)
            end
            local f = redis.call('HINCRBY', KEYS[1], 'fail', 1)
            if f >= tonumber(ARGV[1]) then
              if redis.call('SET', KEYS[2], '1', 'EX', ARGV[2], 'NX') then return 1 end
            end
            return 0
            """, Long.class);

    /** KEYS[1]=창. 창이 있고 조회 중이 남아 있을 때만 줄인다(없는 키를 만들지 않으려고). */
    static final RedisScript<Long> REFUND = new DefaultRedisScript<>("""
            if tonumber(redis.call('HGET', KEYS[1], 'pending') or '0') > 0 then
              return redis.call('HINCRBY', KEYS[1], 'pending', -1)
            end
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
    public Attempt tryAcquire() {
        String window = prefix + "fail:" + (clock.millis() / 60_000);
        try {
            Long wait = redis.execute(ACQUIRE, List.of(window, blockKey()),
                    String.valueOf(MAX_FAILURES_PER_MINUTE), String.valueOf(WINDOW_TTL.toMillis()),
                    String.valueOf(BLOCK.toSeconds()), String.valueOf(BUSY_RETRY_SECONDS));
            if (wait == null || wait <= 0) {
                return Attempt.allowed(window);
            }
            return Attempt.rejected(wait);
        } catch (DataAccessException e) {
            log.warn("페어링 실패 한도를 확인하지 못해 막지 않고 진행합니다: {}", e.getMessage());
            return Attempt.allowed(null);
        }
    }

    @Override
    public void recordFailure(Attempt attempt) {
        if (attempt == null || attempt.window() == null) {
            return;
        }
        try {
            Long started = redis.execute(FAIL, List.of(attempt.window(), blockKey()),
                    String.valueOf(MAX_FAILURES_PER_MINUTE), String.valueOf(BLOCK.toSeconds()));
            if (started != null && started == 1) {
                log.warn("페어링 코드 실패가 1분에 {}번에 닿아 {}초 동안 교환을 막습니다", MAX_FAILURES_PER_MINUTE,
                        BLOCK.toSeconds());
            }
        } catch (DataAccessException e) {
            log.warn("페어링 실패를 세지 못했습니다: {}", e.getMessage());
        }
    }

    @Override
    public void refund(Attempt attempt) {
        if (attempt == null || attempt.window() == null) {
            return;
        }
        try {
            redis.execute(REFUND, List.of(attempt.window()));
        } catch (DataAccessException e) {
            log.warn("페어링 시도를 풀지 못했습니다: {}", e.getMessage());
        }
    }

    private String blockKey() {
        return prefix + "block";
    }
}
