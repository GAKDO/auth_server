package com.gakdo.trace.auth.social.domain;

import java.util.Locale;
import java.util.Optional;

/** 소셜 로그인 제공자. 주소 경로에는 소문자(google·github·kakao·naver)로 쓴다. */
public enum SocialProvider {
    GOOGLE("https://accounts.google.com/o/oauth2/v2/auth", "openid email profile"),
    GITHUB("https://github.com/login/oauth/authorize", "read:user user:email"),
    KAKAO("https://kauth.kakao.com/oauth/authorize", "account_email profile_nickname"),
    NAVER("https://nid.naver.com/oauth2.0/authorize", null);

    private final String authorizeUrl;
    private final String scope;

    SocialProvider(String authorizeUrl, String scope) {
        this.authorizeUrl = authorizeUrl;
        this.scope = scope;
    }

    public String authorizeUrl() {
        return authorizeUrl;
    }

    /** 요청할 권한. 네이버는 앱 설정에서 고른 항목을 쓰므로 null. */
    public String scope() {
        return scope;
    }

    public String pathName() {
        return name().toLowerCase(Locale.ROOT);
    }

    public static Optional<SocialProvider> fromPath(String value) {
        for (SocialProvider p : values()) {
            if (p.pathName().equals(value)) {
                return Optional.of(p);
            }
        }
        return Optional.empty();
    }
}
