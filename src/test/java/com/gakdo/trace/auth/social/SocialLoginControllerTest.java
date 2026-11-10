package com.gakdo.trace.auth.social;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.List;
import java.util.Optional;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.gakdo.trace.auth.account.application.LoginResult;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.social.api.SocialLoginController;
import com.gakdo.trace.auth.social.application.OAuthStateStore;
import com.gakdo.trace.auth.social.application.SocialLoginError;
import com.gakdo.trace.auth.social.application.SocialLoginException;
import com.gakdo.trace.auth.social.application.SocialLoginService;
import com.gakdo.trace.auth.social.application.SocialProfile;
import com.gakdo.trace.auth.social.application.SocialProviderClient;
import com.gakdo.trace.auth.social.domain.SocialProvider;
import com.gakdo.trace.auth.support.WebSliceConfig;

import jakarta.servlet.http.Cookie;

/** 소셜 로그인 시작·콜백 리다이렉트와 쿠키. Google·GitHub만 키가 있는 상태로 확인한다. */
@WebMvcTest(controllers = SocialLoginController.class, properties = {
        "trace.auth.web-public-url=https://gakdo.site",
        "trace.auth.social.google.client-id=google-id", "trace.auth.social.google.client-secret=google-secret",
        "trace.auth.social.github.client-id=github-id", "trace.auth.social.github.client-secret=github-secret"})
@Import(WebSliceConfig.class)
class SocialLoginControllerTest {

    private static final String STATE = "state-abc";

    @Autowired
    MockMvc mvc;
    @MockitoBean
    OAuthStateStore states;
    @MockitoBean
    SocialProviderClient providerClient;
    @MockitoBean
    SocialLoginService loginService;

    @Test
    @DisplayName("키가 설정된 제공자만 목록에 나온다")
    void listsOnlyConfiguredProviders() throws Exception {
        mvc.perform(get("/api/v1/auth/oauth/providers"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.providers").value(org.hamcrest.Matchers.contains("GOOGLE", "GITHUB")));
    }

    @Test
    @DisplayName("시작하면 state 쿠키를 심고 GitHub 인증 화면으로 콜백 주소·이메일 권한과 함께 보낸다")
    void startRedirectsToProvider() throws Exception {
        given(states.issue(SocialProvider.GITHUB, "/rentals/r1")).willReturn(STATE);

        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/start").param("next", "/rentals/r1"))
                .andExpect(status().isFound())
                .andReturn();

        String location = result.getResponse().getHeader("Location");
        assertThat(location).startsWith("https://github.com/login/oauth/authorize?")
                .contains("client_id=github-id")
                .contains("redirect_uri=https://gakdo.site/api/v1/auth/oauth/github/callback")
                .contains("state=" + STATE)
                .contains("scope=read:user%20user:email")
                .doesNotContain("github-secret");
        assertThat(result.getResponse().getHeaders("Set-Cookie")).singleElement().asString()
                .contains("trace_oauth_state=" + STATE).contains("HttpOnly").contains("SameSite=Lax")
                .contains("Path=/api/v1/auth/oauth");
    }

    @Test
    @DisplayName("사이트 밖 주소를 next로 주면 버리고 시작한다")
    void dropsExternalNext() throws Exception {
        given(states.issue(SocialProvider.GOOGLE, "")).willReturn(STATE);
        mvc.perform(get("/api/v1/auth/oauth/google/start").param("next", "//evil.example"))
                .andExpect(status().isFound());
        verify(states).issue(SocialProvider.GOOGLE, "");
    }

    @Test
    @DisplayName("키가 없는 제공자로 시작하면 로그인 화면으로 UNAVAILABLE을 실어 돌려보낸다")
    void unconfiguredProviderIsUnavailable() throws Exception {
        mvc.perform(get("/api/v1/auth/oauth/kakao/start"))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=UNAVAILABLE"));
        verify(states, never()).issue(any(), any());
    }

    @Test
    @DisplayName("모르는 제공자 이름은 404")
    void unknownProviderIs404() throws Exception {
        mvc.perform(get("/api/v1/auth/oauth/facebook/start")).andExpect(status().isNotFound());
    }

    @Test
    @DisplayName("콜백이 성공하면 리프레시 쿠키를 심고 시작할 때의 next로 로그인 화면에 돌려보낸다")
    void callbackSetsRefreshCookie() throws Exception {
        given(states.consume(SocialProvider.GITHUB, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("/rentals/r1")));
        SocialProfile profile = new SocialProfile(SocialProvider.GITHUB, "1", "dev@example.com", "dev");
        given(providerClient.fetchProfile(SocialProvider.GITHUB, "code-1",
                "https://gakdo.site/api/v1/auth/oauth/github/callback", STATE)).willReturn(profile);
        given(loginService.login(profile)).willReturn(new LoginResult(null, "refresh-1", AccountRole.CUSTOMER));

        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/callback")
                        .param("code", "code-1").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", STATE)))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "https://gakdo.site/login?next=/rentals/r1"))
                .andReturn();

        List<String> cookies = result.getResponse().getHeaders("Set-Cookie");
        assertThat(cookies).anySatisfy(c -> assertThat(c).startsWith("trace_refresh=refresh-1")
                .contains("HttpOnly").contains("SameSite=Strict").contains("Path=/api/v1/auth"))
                .anySatisfy(c -> assertThat(c).startsWith("trace_oauth_state=").contains("Max-Age=0"));
    }

    @Test
    @DisplayName("state 쿠키가 없거나 다르면(다른 브라우저에서 시작) 제공자를 부르지 않고 STATE_INVALID")
    void callbackRejectsForeignState() throws Exception {
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("code", "c").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", "other")))
                .andExpect(status().isFound())
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=STATE_INVALID"));
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("code", "c").param("state", STATE))
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=STATE_INVALID"));
        verify(providerClient, never()).fetchProfile(any(), anyString(), anyString(), anyString());
    }

    @Test
    @DisplayName("사용자가 제공자 화면에서 취소하면 CANCELLED")
    void callbackCancelled() throws Exception {
        given(states.consume(SocialProvider.GOOGLE, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("")));
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("error", "access_denied").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", STATE)))
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=CANCELLED"));
    }

    @Test
    @DisplayName("인증된 이메일이 없으면 EMAIL_REQUIRED로 돌려보내고 쿠키를 심지 않는다")
    void callbackEmailRequired() throws Exception {
        given(states.consume(SocialProvider.GITHUB, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("/me")));
        SocialProfile profile = new SocialProfile(SocialProvider.GITHUB, "1", null, "dev");
        given(providerClient.fetchProfile(eq(SocialProvider.GITHUB), anyString(), anyString(), anyString()))
                .willReturn(profile);
        given(loginService.login(profile))
                .willThrow(new SocialLoginException(SocialLoginError.EMAIL_REQUIRED, "no email"));

        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/callback").param("code", "c")
                        .param("state", STATE).cookie(new Cookie("trace_oauth_state", STATE)))
                .andExpect(header().string("Location", "https://gakdo.site/login?next=/me&socialError=EMAIL_REQUIRED"))
                .andReturn();
        assertThat(result.getResponse().getHeaders("Set-Cookie")).noneMatch(c -> c.startsWith("trace_refresh="));
    }
}
