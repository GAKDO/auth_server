// 이 파일이 확인하는 것: 소셜 로그인(구글·깃허브·카카오·네이버) 시작·콜백 주소의 동작.
// 흐름: 로그인 화면에서 버튼 → 시작 주소가 제공자 로그인 화면으로 보냄 → 제공자가 콜백 주소로 돌려보냄 → 로그인 완료.
// 여기서는 구글·깃허브만 키가 설정된 상태로 시험한다(설정 값은 테스트용 가짜).

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
// (도구) @WebMvcTest = 서버 전체 대신 지정한 컨트롤러(소셜 로그인)만 띄우는 가벼운 API 테스트. properties로 사이트 주소와 구글·깃허브 가짜 키만 넣는다
@WebMvcTest(controllers = SocialLoginController.class, properties = {
        "trace.auth.web-public-url=https://gakdo.site",
        "trace.auth.social.google.client-id=google-id", "trace.auth.social.google.client-secret=google-secret",
        "trace.auth.social.github.client-id=github-id", "trace.auth.social.github.client-secret=github-secret"})
// 운영과 같은 보안 규칙·토큰 도구도 함께 띄운다
@Import(WebSliceConfig.class)
class SocialLoginControllerTest {

    // 위조 방지 값(state) 예시
    private static final String STATE = "state-abc";

    // (도구) MockMvc = 진짜 네트워크 없이 HTTP 요청을 흉내 내는 도구. @Autowired = 스프링이 넣어 준다
    @Autowired
    MockMvc mvc;
    // (도구) @MockitoBean = 진짜 대신 가짜(목)를 스프링에 끼워 넣는다. state 저장소(Redis)를 가짜로
    @MockitoBean
    OAuthStateStore states;
    // 제공자(구글 등)와 통신하는 클라이언트도 가짜로
    @MockitoBean
    SocialProviderClient providerClient;
    // 계정 연결·로그인 처리 서비스도 가짜로 = 컨트롤러의 주소 이동·쿠키만 시험한다
    @MockitoBean
    SocialLoginService loginService;

    // [상황] 로그인 화면이 쓸 수 있는 소셜 로그인 목록을 묻는다.
    // [기대] 키가 설정된 구글·깃허브만 나온다(카카오·네이버 버튼은 숨김).
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("키가 설정된 제공자만 목록에 나온다")
    void listsOnlyConfiguredProviders() throws Exception {
        // (도구) perform(get(주소)) = GET 요청을 보낸다. andExpect(...) = 응답 검사
        // 실행: 쓸 수 있는 소셜 로그인 목록을 묻는다
        mvc.perform(get("/api/v1/auth/oauth/providers"))
                // (도구) status().isOk() = 응답 코드가 200(정상)인지 본다
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸을 꺼낸다. contains(a, b) = 정확히 그 순서로 그것만 있어야 통과
                // 확인: 키가 있는 GOOGLE·GITHUB만 나와야 한다
                .andExpect(jsonPath("$.providers").value(org.hamcrest.Matchers.contains("GOOGLE", "GITHUB")));
    }

    // [상황] 깃허브 로그인을 시작한다(끝나면 /rentals/r1로 돌아가고 싶음).
    // [기대] 깃허브 로그인 화면으로 보내며 앱 ID·콜백 주소·state(위조 방지 값)·이메일 읽기 권한을 붙인다.
    //        비밀 키는 주소에 넣지 않는다. 같은 state를 쿠키로도 심어 둔다.
    @Test
    @DisplayName("시작하면 state 쿠키를 심고 GitHub 인증 화면으로 콜백 주소·이메일 권한과 함께 보낸다")
    void startRedirectsToProvider() throws Exception {
        // (도구) given(가짜.메서드(값)).willReturn(결과) = when().thenReturn()과 같은 뜻. "이 호출이 오면 이 값을 돌려줘"
        // 준비: 깃허브 로그인 시작(돌아갈 곳 /rentals/r1)에 state 값을 발급하게 한다
        given(states.issue(SocialProvider.GITHUB, "/rentals/r1")).willReturn(STATE);

        // (도구) param(이름, 값) = 주소 뒤에 ?이름=값을 붙인다. MvcResult = 응답 전체를 담아 두는 그릇
        // 실행: 깃허브 로그인 시작 주소를 부른다
        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/start").param("next", "/rentals/r1"))
                // (도구) status().isFound() = 응답 코드가 302(다른 주소로 이동)인지 본다
                // 확인: 302로 다른 곳으로 보내야 한다
                .andExpect(status().isFound())
                // 응답을 꺼내 둔다
                .andReturn();

        // 이동할 주소(Location 머리말)를 꺼낸다
        String location = result.getResponse().getHeader("Location");
        // (도구) assertThat(값).startsWith(글자) = 그 글자로 시작해야, contains = 들어 있어야, doesNotContain = 없어야 통과
        // 확인: 깃허브 로그인 화면 주소여야 하고
        assertThat(location).startsWith("https://github.com/login/oauth/authorize?")
                // 앱 ID가 붙어 있어야 하고
                .contains("client_id=github-id")
                // 돌아올 콜백 주소가 붙어 있어야 하고
                .contains("redirect_uri=https://gakdo.site/api/v1/auth/oauth/github/callback")
                // 위조 방지 state 값이 붙어 있어야 하고
                .contains("state=" + STATE)
                // 사용자·이메일 읽기 권한을 요청해야 하며
                .contains("scope=read:user%20user:email")
                // 비밀 키는 주소에 없어야 한다
                .doesNotContain("github-secret");
        // (도구) singleElement() = 딱 하나만 있어야 하고 그 하나를 꺼낸다
        // 확인: 쿠키가 하나 심겨야 하고
        assertThat(result.getResponse().getHeaders("Set-Cookie")).singleElement().asString()
                // 같은 state 값을 담고, 스크립트가 못 읽으며(HttpOnly), 다른 사이트 요청엔 제한(SameSite=Lax)돼야 하고
                .contains("trace_oauth_state=" + STATE).contains("HttpOnly").contains("SameSite=Lax")
                // 소셜 로그인 주소에서만 보내져야 한다
                .contains("Path=/api/v1/auth/oauth");
    }

    // [상황] 끝나고 돌아갈 주소로 사이트 밖 주소(//evil.example)를 준다.
    // [기대] 그 주소는 버리고 시작한다(로그인 뒤 피싱 사이트로 보내는 공격 방지).
    @Test
    @DisplayName("사이트 밖 주소를 next로 주면 버리고 시작한다")
    void dropsExternalNext() throws Exception {
        // 준비: 구글 시작(돌아갈 곳 없음)에 state를 발급하게 한다
        given(states.issue(SocialProvider.GOOGLE, "")).willReturn(STATE);
        // 실행: 돌아갈 곳으로 사이트 밖 주소를 주고 구글 로그인을 시작한다
        mvc.perform(get("/api/v1/auth/oauth/google/start").param("next", "//evil.example"))
                // 확인: 302로 시작은 돼야 한다
                .andExpect(status().isFound());
        // (도구) verify(가짜).메서드(값) = 그 값으로 불렸는지 확인
        // 확인: 돌아갈 곳을 빈 값으로 바꿔 저장했어야 한다 = 피싱 사이트로 보내지 않는다
        verify(states).issue(SocialProvider.GOOGLE, "");
    }

    // [상황] 키가 없는 카카오로 로그인을 시작한다.
    // [기대] 로그인 화면으로 돌려보내며 "지금 쓸 수 없음(UNAVAILABLE)"을 알린다.
    @Test
    @DisplayName("키가 없는 제공자로 시작하면 로그인 화면으로 UNAVAILABLE을 실어 돌려보낸다")
    void unconfiguredProviderIsUnavailable() throws Exception {
        // 실행: 키가 없는 카카오로 로그인을 시작한다
        mvc.perform(get("/api/v1/auth/oauth/kakao/start"))
                // 확인: 302여야 하고
                .andExpect(status().isFound())
                // (도구) header().string(이름, 값) = 응답 머리말이 그 값이어야 통과
                // 확인: 로그인 화면으로 UNAVAILABLE을 실어 돌려보내야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=UNAVAILABLE"));
        // (도구) never() = 한 번도 불리지 않았어야 통과. any() = 아무 값이나
        // 확인: state를 발급하지 않았어야 한다
        verify(states, never()).issue(any(), any());
    }

    // [상황] 지원하지 않는 페이스북으로 시작한다.
    // [기대] 404.
    //        ※ 응답 코드: 404 = 찾을 수 없음(없는 주소나 데이터)
    @Test
    @DisplayName("모르는 제공자 이름은 404")
    void unknownProviderIs404() throws Exception {
        // (도구) status().isNotFound() = 응답 코드가 404(찾을 수 없음)인지 본다
        // 실행+확인: 지원하지 않는 facebook으로 시작하면 404여야 한다
        mvc.perform(get("/api/v1/auth/oauth/facebook/start")).andExpect(status().isNotFound());
    }

    // [상황] 깃허브 로그인을 마치고 콜백으로 돌아온다(state 쿠키 일치).
    // [기대] 로그인 유지용 리프레시 쿠키를 심고, 처음 원했던 /rentals/r1로 이어지게 로그인 화면으로 보낸다.
    //        다 쓴 state 쿠키는 지운다.
    @Test
    @DisplayName("콜백이 성공하면 리프레시 쿠키를 심고 시작할 때의 next로 로그인 화면에 돌려보낸다")
    void callbackSetsRefreshCookie() throws Exception {
        // 준비: 깃허브 state를 꺼내 쓰면(한 번만) 돌아갈 곳 /rentals/r1이 나오게 한다
        given(states.consume(SocialProvider.GITHUB, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("/rentals/r1")));
        // 준비: 제공자에게서 받을 사용자 정보(번호 1, 이메일, 이름)
        SocialProfile profile = new SocialProfile(SocialProvider.GITHUB, "1", "dev@example.com", "dev");
        // 준비: 코드 code-1·콜백 주소·state로 사용자 정보를 물으면 위 정보를 주게 한다
        given(providerClient.fetchProfile(SocialProvider.GITHUB, "code-1",
                "https://gakdo.site/api/v1/auth/oauth/github/callback", STATE)).willReturn(profile);
        // 준비: 그 정보로 로그인하면 리프레시 토큰 refresh-1과 고객 역할을 돌려주게 한다
        given(loginService.login(profile)).willReturn(new LoginResult(null, "refresh-1", AccountRole.CUSTOMER));

        // (도구) cookie(쿠키) = 요청에 쿠키를 함께 보낸다
        // 실행: 코드·state와 같은 state 쿠키를 담아 깃허브 콜백 주소를 부른다
        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/callback")
                        .param("code", "code-1").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", STATE)))
                // 확인: 302여야 하고
                .andExpect(status().isFound())
                // 확인: 처음 원했던 /rentals/r1로 이어지게 로그인 화면으로 보내야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?next=/rentals/r1"))
                // 응답을 꺼내 둔다
                .andReturn();

        // 심은 쿠키 목록을 꺼낸다
        List<String> cookies = result.getResponse().getHeaders("Set-Cookie");
        // (도구) anySatisfy(검사) = 목록 중 하나라도 그 검사를 통과하면 된다
        // 확인: 리프레시 쿠키(refresh-1)가 HttpOnly·SameSite=Strict·인증 주소 전용으로 심겨야 하고
        assertThat(cookies).anySatisfy(c -> assertThat(c).startsWith("trace_refresh=refresh-1")
                .contains("HttpOnly").contains("SameSite=Strict").contains("Path=/api/v1/auth"))
                // 다 쓴 state 쿠키는 Max-Age=0으로 지워져야 한다
                .anySatisfy(c -> assertThat(c).startsWith("trace_oauth_state=").contains("Max-Age=0"));
    }

    // [상황] state 쿠키가 다르거나 없다(다른 브라우저에서 시작했거나 위조된 콜백).
    // [기대] 제공자에게 묻지도 않고 STATE_INVALID로 로그인 화면에 돌려보낸다.
    @Test
    @DisplayName("state 쿠키가 없거나 다르면(다른 브라우저에서 시작) 제공자를 부르지 않고 STATE_INVALID")
    void callbackRejectsForeignState() throws Exception {
        // 실행: state 쿠키가 다른 값(other)인 채로 콜백을 부른다
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("code", "c").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", "other")))
                // 확인: 302여야 하고
                .andExpect(status().isFound())
                // 확인: STATE_INVALID로 로그인 화면에 돌려보내야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=STATE_INVALID"));
        // 실행: state 쿠키 없이 콜백을 부른다
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("code", "c").param("state", STATE))
                // 확인: 역시 STATE_INVALID여야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=STATE_INVALID"));
        // (도구) anyString() = 아무 문자열이나
        // 확인: 제공자에게 사용자 정보를 묻지도 않았어야 한다 = 위조된 콜백을 일찍 막는다
        verify(providerClient, never()).fetchProfile(any(), anyString(), anyString(), anyString());
    }

    // [상황] 고객이 구글 로그인 화면에서 "취소"를 눌렀다.
    // [기대] CANCELLED로 로그인 화면에 돌려보낸다.
    @Test
    @DisplayName("사용자가 제공자 화면에서 취소하면 CANCELLED")
    void callbackCancelled() throws Exception {
        // 준비: 구글 state를 꺼내 쓰면 돌아갈 곳 없음이 나오게 한다
        given(states.consume(SocialProvider.GOOGLE, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("")));
        // 실행: 제공자가 "거부(access_denied)"를 실어 콜백을 부른다(고객이 취소)
        mvc.perform(get("/api/v1/auth/oauth/google/callback").param("error", "access_denied").param("state", STATE)
                        .cookie(new Cookie("trace_oauth_state", STATE)))
                // 확인: CANCELLED로 로그인 화면에 돌려보내야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?socialError=CANCELLED"));
    }

    // [상황] 깃허브에서 인증된 이메일을 받지 못했다.
    // [기대] EMAIL_REQUIRED로 돌려보내고 로그인 쿠키는 심지 않는다(TRACE는 이메일이 꼭 필요).
    @Test
    @DisplayName("인증된 이메일이 없으면 EMAIL_REQUIRED로 돌려보내고 쿠키를 심지 않는다")
    void callbackEmailRequired() throws Exception {
        // 준비: 깃허브 state를 꺼내 쓰면 돌아갈 곳 /me가 나오게 한다
        given(states.consume(SocialProvider.GITHUB, STATE))
                .willReturn(Optional.of(new OAuthStateStore.PendingLogin("/me")));
        // 준비: 이메일이 없는(null) 사용자 정보
        SocialProfile profile = new SocialProfile(SocialProvider.GITHUB, "1", null, "dev");
        // (도구) eq(값) = 그 값일 때만
        // 준비: 깃허브 사용자 정보를 물으면 위 정보를 주게 한다
        given(providerClient.fetchProfile(eq(SocialProvider.GITHUB), anyString(), anyString(), anyString()))
                .willReturn(profile);
        // (도구) willThrow(예외) = 그 호출이 오면 예외를 던지게 한다
        // 준비: 그 정보로 로그인하면 EMAIL_REQUIRED 예외가 나게 한다
        given(loginService.login(profile))
                .willThrow(new SocialLoginException(SocialLoginError.EMAIL_REQUIRED, "no email"));

        // 실행: 올바른 state 쿠키로 콜백을 부른다
        MvcResult result = mvc.perform(get("/api/v1/auth/oauth/github/callback").param("code", "c")
                        .param("state", STATE).cookie(new Cookie("trace_oauth_state", STATE)))
                // 확인: 돌아갈 곳(/me)과 EMAIL_REQUIRED를 실어 로그인 화면으로 보내야 한다
                .andExpect(header().string("Location", "https://gakdo.site/login?next=/me&socialError=EMAIL_REQUIRED"))
                // 응답을 꺼내 둔다
                .andReturn();
        // (도구) noneMatch(조건) = 조건에 맞는 것이 하나도 없어야 통과
        // 확인: 로그인 쿠키(trace_refresh)는 심지 않았어야 한다
        assertThat(result.getResponse().getHeaders("Set-Cookie")).noneMatch(c -> c.startsWith("trace_refresh="));
    }
}
