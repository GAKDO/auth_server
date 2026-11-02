package com.gakdo.trace.auth.token.infra;

import java.time.Duration;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;

/**
 * 설계서 "폐기" 규칙: trace:auth:refresh:{jti}에 계정 publicId, 계정별 jti 집합 trace:auth:refresh:account:{id}.
 * jti는 토큰 원문의 SHA-256이라 Redis가 새어도 쿠키를 만들 수 없다.
 */
@Component
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private final StringRedisTemplate redis;
    private final SecureTokens tokens;
    private final String prefix;
    private final Duration ttl;

    public RedisRefreshTokenStore(StringRedisTemplate redis, SecureTokens tokens, AuthProperties properties) {
        this.redis = redis;
        this.tokens = tokens;
        this.prefix = properties.redisKeyPrefix() + "auth:refresh:";
        this.ttl = properties.refreshTokenTtl();
    }

    @Override
    public String issue(String accountId) {
        String token = tokens.opaqueToken();
        String jti = Sha256.hex(token);
        redis.opsForValue().set(tokenKey(jti), accountId, ttl);
        String accountKey = accountKey(accountId);
        redis.opsForSet().add(accountKey, jti);
        redis.expire(accountKey, ttl);
        return token;
    }

    @Override
    public Optional<String> consume(String token) {
        String jti = Sha256.hex(token);
        String key = tokenKey(jti);
        String accountId = redis.opsForValue().get(key);
        // 동시에 두 번 오면 delete가 true인 쪽만 받아들인다(GETDEL이 없는 Redis에서도 한 번만)
        if (accountId == null || !Boolean.TRUE.equals(redis.delete(key))) {
            return Optional.empty();
        }
        redis.opsForSet().remove(accountKey(accountId), jti);
        return Optional.of(accountId);
    }

    @Override
    public void revoke(String token) {
        consume(token);
    }

    @Override
    public void revokeAll(String accountId) {
        String accountKey = accountKey(accountId);
        Set<String> jtis = redis.opsForSet().members(accountKey);
        if (jtis != null) {
            jtis.forEach(jti -> redis.delete(tokenKey(jti)));
        }
        redis.delete(accountKey);
    }

    private String tokenKey(String jti) {
        return prefix + jti;
    }

    private String accountKey(String accountId) {
        return prefix + "account:" + accountId;
    }
}
