package com.gakdo.trace.auth.social.infra;

import java.time.Duration;
import java.util.Optional;

import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.config.SocialProperties;
import com.gakdo.trace.auth.social.application.OAuthStateStore;
import com.gakdo.trace.auth.social.domain.SocialProvider;

/** trace:auth:oauth:state:{sha256(state)} = "{제공자}|{next}", 10분. 꺼낼 때 지워서 한 번만 쓴다. */
@Component
public class RedisOAuthStateStore implements OAuthStateStore {

    private final StringRedisTemplate redis;
    private final SecureTokens tokens;
    private final String prefix;
    private final Duration ttl;

    public RedisOAuthStateStore(StringRedisTemplate redis, SecureTokens tokens, AuthProperties properties,
                                SocialProperties socialProperties) {
        this.redis = redis;
        this.tokens = tokens;
        this.prefix = properties.redisKeyPrefix() + "auth:oauth:state:";
        this.ttl = socialProperties.stateTtl();
    }

    @Override
    public String issue(SocialProvider provider, String next) {
        String state = tokens.opaqueToken();
        redis.opsForValue().set(prefix + Sha256.hex(state), provider.name() + "|" + (next == null ? "" : next), ttl);
        return state;
    }

    @Override
    public Optional<PendingLogin> consume(SocialProvider provider, String state) {
        if (state == null || state.isBlank()) {
            return Optional.empty();
        }
        String key = prefix + Sha256.hex(state);
        String value = redis.opsForValue().get(key);
        if (value == null || !Boolean.TRUE.equals(redis.delete(key))) {
            return Optional.empty();
        }
        int bar = value.indexOf('|');
        if (bar < 0 || !value.substring(0, bar).equals(provider.name())) {
            return Optional.empty();
        }
        return Optional.of(new PendingLogin(value.substring(bar + 1)));
    }
}
