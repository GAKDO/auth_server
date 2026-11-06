package com.gakdo.trace.auth.account.infra;

import java.util.concurrent.TimeUnit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.account.application.ResendGuard;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.config.EmailCodeProperties;

/**
 * 키 trace:auth:email-resend:{용도}:{이메일 SHA-256}을 SET NX EX 60으로 연다. 키에 이메일 원문은 넣지 않는다.
 * Redis가 안 되면 막지 않는다(로그만). gateway의 IP당 요청 제한은 그대로 남는다.
 */
@Component
public class RedisResendGuard implements ResendGuard {

    private static final Logger log = LoggerFactory.getLogger(RedisResendGuard.class);

    private final StringRedisTemplate redis;
    private final String prefix;
    private final EmailCodeProperties properties;

    public RedisResendGuard(StringRedisTemplate redis, AuthProperties authProperties,
                            EmailCodeProperties properties) {
        this.redis = redis;
        this.prefix = authProperties.redisKeyPrefix() + "auth:email-resend:";
        this.properties = properties;
    }

    @Override
    public long tryAcquire(EmailTokenPurpose purpose, String normalizedEmail) {
        String key = prefix + purpose.name().toLowerCase() + ":" + Sha256.hex(normalizedEmail);
        long seconds = Math.max(1, properties.resendInterval().toSeconds());
        try {
            Boolean opened = redis.opsForValue().setIfAbsent(key, "1", seconds, TimeUnit.SECONDS);
            if (Boolean.TRUE.equals(opened)) {
                return 0;
            }
            Long ttl = redis.getExpire(key, TimeUnit.SECONDS);
            return ttl == null || ttl <= 0 ? 1 : ttl;
        } catch (DataAccessException e) {
            log.warn("재발송 제한을 확인하지 못해 막지 않습니다: {}", e.getClass().getSimpleName());
            return 0;
        }
    }
}
