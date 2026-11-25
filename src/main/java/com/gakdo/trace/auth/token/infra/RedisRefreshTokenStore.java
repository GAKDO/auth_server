package com.gakdo.trace.auth.token.infra;

import java.time.Duration;
import java.time.Instant;
import java.util.Optional;
import java.util.Set;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.token.domain.RefreshGrant;

/**
 * 설계서 "폐기" 규칙: trace:auth:refresh:{jti}에 "계정 publicId|로그인 시각(초)", 계정별 jti 집합 trace:auth:refresh:account:{id}.
 * publicId는 NanoID라 '|'가 들어가지 않는다. '|'가 없는 옛 값은 로그인 시각을 모르는 것으로 읽는다.
 * jti는 토큰 원문의 SHA-256이라 Redis가 새어도 쿠키를 만들 수 없다.
 */
@Component
public class RedisRefreshTokenStore implements RefreshTokenStore {

    private static final char SEPARATOR = '|';

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
    public String issue(String accountId, Instant authTime) {
        String token = tokens.opaqueToken();
        String jti = Sha256.hex(token);
        String value = authTime == null ? accountId : accountId + SEPARATOR + authTime.getEpochSecond();
        redis.opsForValue().set(tokenKey(jti), value, ttl);
        String accountKey = accountKey(accountId);
        redis.opsForSet().add(accountKey, jti);
        redis.expire(accountKey, ttl);
        return token;
    }

    @Override
    public Optional<RefreshGrant> consume(String token) {
        String jti = Sha256.hex(token);
        String key = tokenKey(jti);
        String value = redis.opsForValue().get(key);
        // 동시에 두 번 오면 delete가 true인 쪽만 받아들인다(GETDEL이 없는 Redis에서도 한 번만)
        if (value == null || !Boolean.TRUE.equals(redis.delete(key))) {
            return Optional.empty();
        }
        RefreshGrant grant = parse(value);
        redis.opsForSet().remove(accountKey(grant.accountId()), jti);
        return Optional.of(grant);
    }

    static RefreshGrant parse(String value) {
        int at = value.indexOf(SEPARATOR);
        if (at < 0) {
            return new RefreshGrant(value, null);
        }
        Instant authTime;
        try {
            authTime = Instant.ofEpochSecond(Long.parseLong(value.substring(at + 1)));
        } catch (NumberFormatException e) {
            authTime = null;
        }
        return new RefreshGrant(value.substring(0, at), authTime);
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
