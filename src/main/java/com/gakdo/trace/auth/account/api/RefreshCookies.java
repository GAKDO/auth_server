package com.gakdo.trace.auth.account.api;

import java.time.Duration;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseCookie;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;

/** 리프레시 쿠키 trace_refresh(HttpOnly, SameSite=Strict, Path=/api/v1/auth). 비밀번호 로그인과 소셜 로그인이 같이 쓴다. */
@Component
public class RefreshCookies {

    public static final String NAME = "trace_refresh";
    private final AuthProperties properties;
    private final String path;

    /** @param path 쿠키 Path. 기본은 인증 API 경로(/api/v1/auth)이고 trace.auth.cookie-path로 바꿀 수 있다 */
    public RefreshCookies(AuthProperties properties, @Value("${trace.auth.cookie-path:/api/v1/auth}") String path) {
        this.properties = properties;
        this.path = path;
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
                .path(path)
                .maxAge(maxAge)
                .build();
    }
}
