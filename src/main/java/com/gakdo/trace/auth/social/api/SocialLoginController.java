package com.gakdo.trace.auth.social.api;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.time.Duration;
import java.util.Arrays;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CookieValue;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.UriComponentsBuilder;

import com.gakdo.trace.auth.account.api.RefreshCookies;
import com.gakdo.trace.auth.account.application.LoginResult;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.config.SocialProperties;
import com.gakdo.trace.auth.social.application.OAuthStateStore;
import com.gakdo.trace.auth.social.application.SocialLoginError;
import com.gakdo.trace.auth.social.application.SocialLoginException;
import com.gakdo.trace.auth.social.application.SocialLoginService;
import com.gakdo.trace.auth.social.application.SocialProfile;
import com.gakdo.trace.auth.social.application.SocialProviderClient;
import com.gakdo.trace.auth.social.domain.SocialProvider;

/**
 * 소셜 로그인(contracts auth-server.yaml /api/v1/auth/oauth/*). 브라우저가 주소를 직접 여는 경로라 JSON이 아니라 302로 답한다.
 * 성공하면 리프레시 쿠키를 심고 웹 /login?next=… 로 보내고, 웹은 기존 /refresh로 세션을 연다.
 * 실패하면 /login?socialError=<SocialLoginError> 로 보낸다.
 */
@RestController
@RequestMapping("/api/v1/auth/oauth")
public class SocialLoginController {

    static final String STATE_COOKIE = "trace_oauth_state";
    private static final int NEXT_MAX = 512;
    private static final Logger log = LoggerFactory.getLogger(SocialLoginController.class);

    private final SocialProperties socialProperties;
    private final AuthProperties authProperties;
    private final OAuthStateStore states;
    private final SocialProviderClient providerClient;
    private final SocialLoginService loginService;
    private final RefreshCookies refreshCookies;

    public SocialLoginController(SocialProperties socialProperties, AuthProperties authProperties,
                                 OAuthStateStore states, SocialProviderClient providerClient,
                                 SocialLoginService loginService, RefreshCookies refreshCookies) {
        this.socialProperties = socialProperties;
        this.authProperties = authProperties;
        this.states = states;
        this.providerClient = providerClient;
        this.loginService = loginService;
        this.refreshCookies = refreshCookies;
    }

    @GetMapping("/providers")
    public SocialProvidersResponse providers() {
        return new SocialProvidersResponse(Arrays.stream(SocialProvider.values())
                .filter(socialProperties::enabled)
                .map(Enum::name)
                .toList());
    }

    @GetMapping("/{provider}/start")
    public ResponseEntity<Void> start(@PathVariable String provider,
                                      @RequestParam(name = "next", required = false) String next) {
        SocialProvider p = parse(provider);
        String safe = safeNext(next);
        if (!socialProperties.enabled(p)) {
            return redirect(loginUrl(safe, SocialLoginError.UNAVAILABLE), null);
        }
        String state = states.issue(p, safe);
        UriComponentsBuilder url = UriComponentsBuilder.fromUriString(p.authorizeUrl())
                .queryParam("response_type", "code")
                .queryParam("client_id", socialProperties.client(p).clientId())
                .queryParam("redirect_uri", callbackUrl(p))
                .queryParam("state", state);
        if (p.scope() != null) {
            url.queryParam("scope", p.scope());
        }
        if (p == SocialProvider.GOOGLE) {
            url.queryParam("prompt", "select_account"); // 공용 PC에서 다른 구글 계정으로 바꿀 수 있게
        }
        return redirect(url.encode().build().toUriString(), stateCookie(state, socialProperties.stateTtl()));
    }

    @GetMapping("/{provider}/callback")
    public ResponseEntity<Void> callback(@PathVariable String provider,
                                         @RequestParam(name = "code", required = false) String code,
                                         @RequestParam(name = "state", required = false) String state,
                                         @RequestParam(name = "error", required = false) String error,
                                         @CookieValue(name = STATE_COOKIE, required = false) String cookieState) {
        SocialProvider p = parse(provider);
        ResponseCookie clearState = stateCookie("", Duration.ZERO);
        // 이 브라우저에서 시작한 로그인인지(state 쿠키) 먼저 보고, 한 번만 쓰도록 저장소에서 꺼낸다
        if (state == null || cookieState == null || !constantTimeEquals(state, cookieState)) {
            return redirect(loginUrl("", SocialLoginError.STATE_INVALID), clearState);
        }
        OAuthStateStore.PendingLogin pending = states.consume(p, state).orElse(null);
        if (pending == null) {
            return redirect(loginUrl("", SocialLoginError.STATE_INVALID), clearState);
        }
        if (error != null || code == null || code.isBlank()) {
            return redirect(loginUrl(pending.next(), SocialLoginError.CANCELLED), clearState);
        }
        if (!socialProperties.enabled(p)) {
            return redirect(loginUrl(pending.next(), SocialLoginError.UNAVAILABLE), clearState);
        }
        try {
            SocialProfile profile = providerClient.fetchProfile(p, code, callbackUrl(p), state);
            LoginResult result = loginService.login(profile);
            return ResponseEntity.status(HttpStatus.FOUND)
                    .location(URI.create(loginUrl(pending.next(), null)))
                    .header(HttpHeaders.SET_COOKIE, clearState.toString())
                    .header(HttpHeaders.SET_COOKIE, refreshCookies.issue(result.refreshToken()).toString())
                    .build();
        } catch (SocialLoginException e) {
            log.warn("소셜 로그인 실패 provider={} reason={} message={}", p, e.error(), e.getMessage());
            return redirect(loginUrl(pending.next(), e.error()), clearState);
        }
    }

    private static SocialProvider parse(String provider) {
        return SocialProvider.fromPath(provider)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND));
    }

    /** 제공자 앱에 등록할 콜백 주소: {WEB_PUBLIC_URL}/api/v1/auth/oauth/{provider}/callback (같은 출처로 gateway를 거친다). */
    String callbackUrl(SocialProvider p) {
        return baseUrl() + "/api/v1/auth/oauth/" + p.pathName() + "/callback";
    }

    private String loginUrl(String next, SocialLoginError error) {
        UriComponentsBuilder url = UriComponentsBuilder.fromUriString(baseUrl() + "/login");
        if (next != null && !next.isEmpty()) {
            url.queryParam("next", next);
        }
        if (error != null) {
            url.queryParam("socialError", error.name());
        }
        return url.encode().build().toUriString();
    }

    private String baseUrl() {
        String base = authProperties.webPublicUrl();
        return base.endsWith("/") ? base.substring(0, base.length() - 1) : base;
    }

    /** 사이트 안 경로만 받는다("/"로 시작, "//"·"\" 없음). 아니면 빈 값(웹이 기본 화면으로 보낸다). */
    static String safeNext(String next) {
        if (next == null || next.length() > NEXT_MAX || !next.startsWith("/") || next.startsWith("//")
                || next.contains("\\") || next.chars().anyMatch(Character::isISOControl)) {
            return "";
        }
        return next;
    }

    private ResponseCookie stateCookie(String value, Duration maxAge) {
        // 제공자에서 돌아오는 요청은 다른 사이트에서 시작한 GET 이동이라 Lax여야 쿠키가 실린다
        return ResponseCookie.from(STATE_COOKIE, value)
                .httpOnly(true)
                .secure(authProperties.cookieSecure())
                .sameSite("Lax")
                .path(refreshCookies.path() + "/oauth")
                .maxAge(maxAge)
                .build();
    }

    private static ResponseEntity<Void> redirect(String location, ResponseCookie cookie) {
        ResponseEntity.BodyBuilder builder = ResponseEntity.status(HttpStatus.FOUND).location(URI.create(location));
        if (cookie != null) {
            builder.header(HttpHeaders.SET_COOKIE, cookie.toString());
        }
        return builder.build();
    }

    private static boolean constantTimeEquals(String a, String b) {
        return MessageDigest.isEqual(a.getBytes(StandardCharsets.UTF_8), b.getBytes(StandardCharsets.UTF_8));
    }
}
