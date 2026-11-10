package com.gakdo.trace.auth.social.infra;

import java.net.http.HttpClient;
import java.time.Duration;

import org.springframework.http.MediaType;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestClientException;

import com.fasterxml.jackson.databind.JsonNode;
import com.gakdo.trace.auth.config.SocialProperties;
import com.gakdo.trace.auth.social.application.SocialLoginError;
import com.gakdo.trace.auth.social.application.SocialLoginException;
import com.gakdo.trace.auth.social.application.SocialProfile;
import com.gakdo.trace.auth.social.application.SocialProviderClient;
import com.gakdo.trace.auth.social.domain.SocialProvider;

/**
 * 제공자 HTTP 통신. 이메일은 제공자가 인증했다고 알려 준 것만 쓴다.
 * GitHub은 이메일을 비공개로 둔 사용자가 많아 /user/emails에서 인증된 primary를 고른다.
 */
@Component
public class HttpSocialProviderClient implements SocialProviderClient {

    private final RestClient http;
    private final SocialProperties properties;

    public HttpSocialProviderClient(RestClient.Builder builder, SocialProperties properties) {
        HttpClient jdk = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build();
        JdkClientHttpRequestFactory factory = new JdkClientHttpRequestFactory(jdk);
        factory.setReadTimeout(Duration.ofSeconds(10));
        this.http = builder.requestFactory(factory)
                .defaultHeader("User-Agent", "trace-auth-server")
                .build();
        this.properties = properties;
    }

    /** 테스트용: 이미 만든 RestClient를 그대로 쓴다. */
    HttpSocialProviderClient(RestClient http, SocialProperties properties) {
        this.http = http;
        this.properties = properties;
    }

    @Override
    public SocialProfile fetchProfile(SocialProvider provider, String code, String redirectUri, String state) {
        try {
            String accessToken = exchange(provider, code, redirectUri, state);
            return switch (provider) {
                case GOOGLE -> google(accessToken);
                case GITHUB -> github(accessToken);
                case KAKAO -> kakao(accessToken);
                case NAVER -> naver(accessToken);
            };
        } catch (RestClientException e) {
            throw new SocialLoginException(SocialLoginError.PROVIDER_ERROR, provider + " 통신 실패", e);
        }
    }

    private String exchange(SocialProvider provider, String code, String redirectUri, String state) {
        SocialProperties.Client client = properties.client(provider);
        MultiValueMap<String, String> form = new LinkedMultiValueMap<>();
        form.add("grant_type", "authorization_code");
        form.add("code", code);
        form.add("redirect_uri", redirectUri);
        form.add("client_id", client.clientId());
        form.add("client_secret", client.clientSecret());
        if (provider == SocialProvider.NAVER) {
            form.add("state", state);
        }
        JsonNode body = http.post().uri(tokenUrl(provider))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .accept(MediaType.APPLICATION_JSON)
                .body(form)
                .retrieve()
                .body(JsonNode.class);
        String token = text(body, "access_token");
        if (token == null) {
            // GitHub·네이버는 실패해도 200에 error를 싣는다
            throw new SocialLoginException(SocialLoginError.PROVIDER_ERROR,
                    provider + " 토큰 교환 실패: " + text(body, "error"));
        }
        return token;
    }

    static String tokenUrl(SocialProvider provider) {
        return switch (provider) {
            case GOOGLE -> "https://oauth2.googleapis.com/token";
            case GITHUB -> "https://github.com/login/oauth/access_token";
            case KAKAO -> "https://kauth.kakao.com/oauth/token";
            case NAVER -> "https://nid.naver.com/oauth2.0/token";
        };
    }

    private JsonNode get(String url, String accessToken) {
        return http.get().uri(url)
                .header("Authorization", "Bearer " + accessToken)
                .accept(MediaType.APPLICATION_JSON)
                .retrieve()
                .body(JsonNode.class);
    }

    private SocialProfile google(String token) {
        JsonNode me = get("https://openidconnect.googleapis.com/v1/userinfo", token);
        boolean verified = me != null && me.path("email_verified").asBoolean(false);
        return new SocialProfile(SocialProvider.GOOGLE, required(me, "sub"),
                verified ? text(me, "email") : null, text(me, "name"));
    }

    private SocialProfile github(String token) {
        JsonNode me = get("https://api.github.com/user", token);
        JsonNode emails = get("https://api.github.com/user/emails", token);
        String email = null;
        if (emails != null && emails.isArray()) {
            for (JsonNode e : emails) {
                if (e.path("verified").asBoolean(false) && e.path("primary").asBoolean(false)) {
                    email = text(e, "email");
                    break;
                }
            }
        }
        String name = text(me, "name");
        return new SocialProfile(SocialProvider.GITHUB, required(me, "id"), email,
                name != null ? name : text(me, "login"));
    }

    private SocialProfile kakao(String token) {
        JsonNode me = get("https://kapi.kakao.com/v2/user/me", token);
        JsonNode account = me == null ? null : me.path("kakao_account");
        boolean verified = account != null && account.path("is_email_verified").asBoolean(false)
                && account.path("is_email_valid").asBoolean(false);
        return new SocialProfile(SocialProvider.KAKAO, required(me, "id"),
                verified ? text(account, "email") : null,
                account == null ? null : text(account.path("profile"), "nickname"));
    }

    private SocialProfile naver(String token) {
        JsonNode me = get("https://openapi.naver.com/v1/nid/me", token);
        JsonNode r = me == null ? null : me.path("response");
        // 네이버는 본인 확인한 계정 이메일만 내준다(인증 여부 칸이 따로 없음)
        String name = text(r, "name");
        return new SocialProfile(SocialProvider.NAVER, required(r, "id"), text(r, "email"),
                name != null ? name : text(r, "nickname"));
    }

    private static String required(JsonNode node, String field) {
        String value = text(node, field);
        if (value == null) {
            throw new SocialLoginException(SocialLoginError.PROVIDER_ERROR, "사용자 번호(" + field + ")가 없음");
        }
        return value;
    }

    private static String text(JsonNode node, String field) {
        if (node == null || node.isMissingNode()) {
            return null;
        }
        JsonNode v = node.get(field);
        if (v == null || v.isNull()) {
            return null;
        }
        String s = v.asText();
        return s.isBlank() ? null : s;
    }
}
