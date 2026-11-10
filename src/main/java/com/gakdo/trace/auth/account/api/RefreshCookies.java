package com.gakdo.trace.auth.account.api;

import java.time.Duration;

import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;

/** 리프레시 쿠키 trace_refresh(HttpOnly, SameSite=Strict, Path=/api/v1/auth). 비밀번호 로그인과 소셜 로그인이 같이 쓴다. */
@Component
public class RefreshCookies {

    public static final String NAME = "trace_refresh";
    private static final String PATH = "/api/v1/auth";

    private final AuthProperties properties;

    public RefreshCookies(AuthProperties properties) {
        this.properties = properties;
    }

    public ResponseCookie issue(String refreshToken) {
        return build(refreshToken, properties.refreshTokenTtl());
    }

    public ResponseCookie clear() {
        return build("", Duration.ZERO);
    }

    private ResponseCookie build(String value, Duration maxAge) {
        return ResponseCookie.from(NAME, value)
                .httpOnly(true)
                .secure(properties.cookieSecure())
                .sameSite("Strict")
                .path(PATH)
                .maxAge(maxAge)
                .build();
    }
}
