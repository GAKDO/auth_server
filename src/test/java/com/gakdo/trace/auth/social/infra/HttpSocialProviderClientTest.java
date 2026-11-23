// 이 파일이 확인하는 것: 각 소셜 제공자(구글·깃허브·카카오·네이버) 응답에서 사용자 번호와 "인증된" 이메일을 읽는 규칙.
// 진짜 제공자 대신 정해 둔 응답을 돌려주는 가짜 서버를 쓴다. 키 값은 테스트용 가짜.

package com.gakdo.trace.auth.social.infra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.content;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.header;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.method;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.requestTo;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.test.web.client.MockRestServiceServer;
import org.springframework.web.client.RestClient;

import com.gakdo.trace.auth.config.SocialProperties;
import com.gakdo.trace.auth.social.application.SocialLoginError;
import com.gakdo.trace.auth.social.application.SocialLoginException;
import com.gakdo.trace.auth.social.application.SocialProfile;
import com.gakdo.trace.auth.social.domain.SocialProvider;

/** 제공자 응답에서 사용자 번호·인증된 이메일을 읽는 규칙(네트워크 없이 MockRestServiceServer). */
class HttpSocialProviderClientTest {

    private static final String REDIRECT = "https://gakdo.site/api/v1/auth/oauth/x/callback";
    private MockRestServiceServer server;
    private HttpSocialProviderClient client;

    @BeforeEach
    void setUp() {
        RestClient.Builder builder = RestClient.builder();
        server = MockRestServiceServer.bindTo(builder).build();
        SocialProperties props = new SocialProperties(null, new SocialProperties.Client("gid", "gsecret"),
                new SocialProperties.Client("hid", "hsecret"), new SocialProperties.Client("kid", "ksecret"),
                new SocialProperties.Client("nid", "nsecret"));
        client = new HttpSocialProviderClient(builder.build(), props);
    }

    // [상황] 깃허브 사용자가 이메일을 비공개로 해 두었다.
    // [기대] 이메일 목록 주소에서 인증된 대표(primary) 이메일을 골라 쓴다.
    @Test
    @DisplayName("GitHub 이메일이 비공개여도 /user/emails에서 인증된 primary 이메일을 고른다")
    void githubPrivateEmail() {
        token("https://github.com/login/oauth/access_token");
        server.expect(requestTo("https://api.github.com/user"))
                .andExpect(header("Authorization", "Bearer at-1"))
                .andRespond(json("{\"id\":42,\"login\":\"octo\",\"name\":null,\"email\":null}"));
        server.expect(requestTo("https://api.github.com/user/emails"))
                .andRespond(json("[{\"email\":\"old@x.com\",\"primary\":false,\"verified\":true},"
                        + "{\"email\":\"main@x.com\",\"primary\":true,\"verified\":true}]"));

        SocialProfile p = client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s");

        assertThat(p).isEqualTo(new SocialProfile(SocialProvider.GITHUB, "42", "main@x.com", "octo"));
        server.verify();
    }

    // [상황] 깃허브 대표 이메일이 아직 인증되지 않았다.
    // [기대] 이메일 없이 돌려준다(남의 이메일로 가입하는 것 방지).
    @Test
    @DisplayName("GitHub primary 이메일이 인증 전이면 이메일 없이 돌려준다")
    void githubUnverifiedPrimary() {
        token("https://github.com/login/oauth/access_token");
        server.expect(requestTo("https://api.github.com/user")).andRespond(json("{\"id\":42,\"login\":\"octo\"}"));
        server.expect(requestTo("https://api.github.com/user/emails"))
                .andRespond(json("[{\"email\":\"main@x.com\",\"primary\":true,\"verified\":false}]"));

        assertThat(client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s").email()).isNull();
    }

    // [상황] 구글이 이메일 인증됨(email_verified=true)을 준다.
    // [기대] 그 이메일과 이름을 쓴다.
    @Test
    @DisplayName("Google은 email_verified가 true일 때만 이메일을 쓴다")
    void googleVerifiedOnly() {
        token("https://oauth2.googleapis.com/token");
        server.expect(requestTo("https://openidconnect.googleapis.com/v1/userinfo"))
                .andRespond(json("{\"sub\":\"g1\",\"email\":\"a@gmail.com\",\"email_verified\":true,\"name\":\"A\"}"));
        assertThat(client.fetchProfile(SocialProvider.GOOGLE, "code", REDIRECT, "s"))
                .isEqualTo(new SocialProfile(SocialProvider.GOOGLE, "g1", "a@gmail.com", "A"));
    }

    // [상황] 카카오가 인증·유효한 이메일과 닉네임을 준다.
    // [기대] 이메일을 쓰고 닉네임을 이름으로 쓴다.
    @Test
    @DisplayName("카카오는 인증·유효한 이메일만 쓰고 닉네임을 이름으로 쓴다")
    void kakao() {
        token("https://kauth.kakao.com/oauth/token");
        server.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                .andRespond(json("{\"id\":7,\"kakao_account\":{\"email\":\"k@kakao.com\",\"is_email_verified\":true,"
                        + "\"is_email_valid\":true,\"profile\":{\"nickname\":\"카카오\"}}}"));
        assertThat(client.fetchProfile(SocialProvider.KAKAO, "code", REDIRECT, "s"))
                .isEqualTo(new SocialProfile(SocialProvider.KAKAO, "7", "k@kakao.com", "카카오"));
    }

    // [상황] 네이버 로그인 토큰을 받는다.
    // [기대] 네이버가 요구하는 state 값을 토큰 요청에 함께 보낸다.
    @Test
    @DisplayName("네이버 토큰 교환에는 state를 함께 보낸다")
    void naverSendsState() {
        server.expect(requestTo("https://nid.naver.com/oauth2.0/token"))
                .andExpect(content().string(org.hamcrest.Matchers.containsString("state=s-1")))
                .andRespond(json("{\"access_token\":\"at-1\"}"));
        server.expect(requestTo("https://openapi.naver.com/v1/nid/me"))
                .andRespond(json("{\"response\":{\"id\":\"n1\",\"email\":\"n@naver.com\",\"name\":\"네이버\"}}"));
        assertThat(client.fetchProfile(SocialProvider.NAVER, "code", REDIRECT, "s-1").email()).isEqualTo("n@naver.com");
    }

    // [상황] 깃허브가 200 응답 안에 오류(bad_verification_code)를 담아 보낸다.
    // [기대] 제공자 오류(PROVIDER_ERROR)로 처리한다.
    //        ※ 응답 코드: 200 = 정상 처리됨
    @Test
    @DisplayName("토큰 교환이 200에 error를 실어 오면 PROVIDER_ERROR")
    void tokenErrorInBody() {
        server.expect(requestTo("https://github.com/login/oauth/access_token"))
                .andRespond(json("{\"error\":\"bad_verification_code\"}"));
        assertThatThrownBy(() -> client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s"))
                .isInstanceOf(SocialLoginException.class)
                .extracting(e -> ((SocialLoginException) e).error())
                .isEqualTo(SocialLoginError.PROVIDER_ERROR);
    }

    // 도우미: "토큰 교환 요청이 오면 테스트용 토큰을 준다"를 가짜 서버에 걸어 둔다.
    private void token(String url) {
        server.expect(requestTo(url)).andExpect(method(HttpMethod.POST))
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                .andRespond(json("{\"access_token\":\"at-1\",\"token_type\":\"bearer\"}"));
    }

    private static org.springframework.test.web.client.ResponseCreator json(String body) {
        return withSuccess(body, MediaType.APPLICATION_JSON);
    }
}
