package com.gakdo.trace.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

import com.gakdo.trace.auth.social.domain.SocialProvider;

/**
 * trace.auth.social.*: 소셜 로그인 제공자별 client id/secret(환경 변수 GOOGLE_CLIENT_ID 등, 값은 trace-secrets·.env).
 * id나 secret이 비어 있는 제공자는 꺼진 것으로 보고 로그인 화면에 버튼을 보이지 않는다.
 */
@ConfigurationProperties(prefix = "trace.auth.social")
public record SocialProperties(Duration stateTtl, Client google, Client github, Client kakao, Client naver) {

    public SocialProperties {
        stateTtl = stateTtl == null ? Duration.ofMinutes(10) : stateTtl;
        google = google == null ? Client.EMPTY : google;
        github = github == null ? Client.EMPTY : github;
        kakao = kakao == null ? Client.EMPTY : kakao;
        naver = naver == null ? Client.EMPTY : naver;
    }

    public record Client(String clientId, String clientSecret) {
        static final Client EMPTY = new Client(null, null);

        public boolean configured() {
            return clientId != null && !clientId.isBlank() && clientSecret != null && !clientSecret.isBlank();
        }
    }

    public Client client(SocialProvider provider) {
        return switch (provider) {
            case GOOGLE -> google;
            case GITHUB -> github;
            case KAKAO -> kakao;
            case NAVER -> naver;
        };
    }

    public boolean enabled(SocialProvider provider) {
        return client(provider).configured();
    }
}
