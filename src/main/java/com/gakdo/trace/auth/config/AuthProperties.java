package com.gakdo.trace.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** trace.auth.* 설정. 수명은 설계서 "인증" 표의 값이 기본이다. */
@ConfigurationProperties(prefix = "trace.auth")
public record AuthProperties(
        String issuer,
        String jwtPrivateKey,
        boolean requireConfiguredKey,
        String redisKeyPrefix,
        String webPublicUrl,
        Duration accessTokenTtl,
        Duration refreshTokenTtl,
        Duration captureTokenTtl,
        Duration boothTokenTtl,
        Duration agentTokenTtl,
        Duration pairingCodeTtl,
        Duration captureLinkTtl,
        boolean cookieSecure,
        InitialAdmin initialAdmin,
        InitialBooth initialBooth,
        DemoCustomer demoCustomer) {

    public record InitialAdmin(String email, String password) {
    }

    public record InitialBooth(String clientId, String clientSecret) {
    }

    /** 시연용 고객 계정(DEMO_CUSTOMER_EMAIL·DEMO_CUSTOMER_PASSWORD). 회원 화면(C)이 없어도 고객 흐름을 시연한다. */
    public record DemoCustomer(String email, String password) {
    }
}
