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

    // 로그인 뒤 돌아올 주소(시험용)
    private static final String REDIRECT = "https://gakdo.site/api/v1/auth/oauth/x/callback";
    // (도구) MockRestServiceServer = 진짜 인터넷 대신 정해 둔 응답을 돌려주는 가짜 서버. 어떤 요청이 와야 하는지도 미리 정한다
    private MockRestServiceServer server;
    // 시험할 소셜 제공자 클라이언트
    private HttpSocialProviderClient client;

    // (도구) @BeforeEach = 각 테스트 전에 매번 먼저 실행할 준비 코드
    @BeforeEach
    void setUp() {
        // 준비: HTTP 호출 도구(RestClient) 만들기 틀을 준비한다
        RestClient.Builder builder = RestClient.builder();
        // 그 틀에 가짜 서버를 묶는다 = 이 틀로 만든 도구는 진짜 인터넷 대신 가짜 서버로 간다
        server = MockRestServiceServer.bindTo(builder).build();
        // 구글·깃허브·카카오·네이버의 시험용 가짜 아이디·비밀 값을 넣은 설정을 만든다
        SocialProperties props = new SocialProperties(null, new SocialProperties.Client("gid", "gsecret"),
                new SocialProperties.Client("hid", "hsecret"), new SocialProperties.Client("kid", "ksecret"),
                new SocialProperties.Client("nid", "nsecret"));
        // 가짜 서버에 묶인 도구와 설정으로 시험할 클라이언트를 만든다
        client = new HttpSocialProviderClient(builder.build(), props);
    }

    // [상황] 깃허브 사용자가 이메일을 비공개로 해 두었다.
    // [기대] 이메일 목록 주소에서 인증된 대표(primary) 이메일을 골라 쓴다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("GitHub 이메일이 비공개여도 /user/emails에서 인증된 primary 이메일을 고른다")
    void githubPrivateEmail() {
        // 준비: 깃허브 토큰 교환 요청이 오면 시험용 토큰을 주게 한다
        token("https://github.com/login/oauth/access_token");
        // (도구) expect(requestTo(주소)) = 이 주소로 요청이 와야 한다. andExpect(header(...)) = 이 머리말이 있어야 한다. andRespond(...) = 이렇게 답한다
        // 준비: 사용자 정보 요청이 와야 하고
        server.expect(requestTo("https://api.github.com/user"))
                // 받은 토큰(at-1)을 붙여 와야 하며
                .andExpect(header("Authorization", "Bearer at-1"))
                // 이메일이 비공개(null)인 사용자 정보로 답한다
                .andRespond(json("{\"id\":42,\"login\":\"octo\",\"name\":null,\"email\":null}"));
        // 준비: 이메일 목록 요청이 와야 하고
        server.expect(requestTo("https://api.github.com/user/emails"))
                // 대표 아님(old)과 대표·인증됨(main) 이메일 목록으로 답한다
                .andRespond(json("[{\"email\":\"old@x.com\",\"primary\":false,\"verified\":true},"
                        + "{\"email\":\"main@x.com\",\"primary\":true,\"verified\":true}]"));

        // 실행: 깃허브 로그인 코드로 사용자 정보를 가져온다
        SocialProfile p = client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s");

        // (도구) assertThat(값).isEqualTo(기대값) = "값이 기대값과 같아야 한다"를 확인하는 AssertJ 도구
        // 확인: 번호 42, 인증된 대표 이메일 main@x.com, 이름 대신 로그인 이름 octo여야 한다
        assertThat(p).isEqualTo(new SocialProfile(SocialProvider.GITHUB, "42", "main@x.com", "octo"));
        // (도구) server.verify() = 미리 정한 요청이 모두 실제로 왔는지 확인
        // 확인: 토큰·사용자·이메일 목록 요청이 모두 갔어야 한다
        server.verify();
    }

    // [상황] 깃허브 대표 이메일이 아직 인증되지 않았다.
    // [기대] 이메일 없이 돌려준다(남의 이메일로 가입하는 것 방지).
    @Test
    @DisplayName("GitHub primary 이메일이 인증 전이면 이메일 없이 돌려준다")
    void githubUnverifiedPrimary() {
        // 준비: 깃허브 토큰 교환 요청에 시험용 토큰을 주게 한다
        token("https://github.com/login/oauth/access_token");
        // 준비: 사용자 정보 요청에는 번호·로그인 이름만 답한다
        server.expect(requestTo("https://api.github.com/user")).andRespond(json("{\"id\":42,\"login\":\"octo\"}"));
        // 준비: 이메일 목록 요청에는
        server.expect(requestTo("https://api.github.com/user/emails"))
                // 대표지만 인증 전(verified=false)인 이메일 하나로 답한다
                .andRespond(json("[{\"email\":\"main@x.com\",\"primary\":true,\"verified\":false}]"));

        // (도구) isNull() = 값이 없어야 통과
        // 실행+확인: 사용자 정보를 가져오면 이메일이 없어야 한다 = 인증 안 된 남의 이메일로 가입 못 하게
        assertThat(client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s").email()).isNull();
    }

    // [상황] 구글이 이메일 인증됨(email_verified=true)을 준다.
    // [기대] 그 이메일과 이름을 쓴다.
    @Test
    @DisplayName("Google은 email_verified가 true일 때만 이메일을 쓴다")
    void googleVerifiedOnly() {
        // 준비: 구글 토큰 교환 요청에 시험용 토큰을 주게 한다
        token("https://oauth2.googleapis.com/token");
        // 준비: 구글 사용자 정보 요청에는
        server.expect(requestTo("https://openidconnect.googleapis.com/v1/userinfo"))
                // 번호 g1, 인증된(email_verified=true) 이메일, 이름 A로 답한다
                .andRespond(json("{\"sub\":\"g1\",\"email\":\"a@gmail.com\",\"email_verified\":true,\"name\":\"A\"}"));
        // 실행+확인: 구글 사용자 정보를 가져오면
        assertThat(client.fetchProfile(SocialProvider.GOOGLE, "code", REDIRECT, "s"))
                // 번호·이메일·이름을 그대로 써야 한다
                .isEqualTo(new SocialProfile(SocialProvider.GOOGLE, "g1", "a@gmail.com", "A"));
    }

    // [상황] 카카오가 인증·유효한 이메일과 닉네임을 준다.
    // [기대] 이메일을 쓰고 닉네임을 이름으로 쓴다.
    @Test
    @DisplayName("카카오는 인증·유효한 이메일만 쓰고 닉네임을 이름으로 쓴다")
    void kakao() {
        // 준비: 카카오 토큰 교환 요청에 시험용 토큰을 주게 한다
        token("https://kauth.kakao.com/oauth/token");
        // 준비: 카카오 사용자 정보 요청에는
        server.expect(requestTo("https://kapi.kakao.com/v2/user/me"))
                // 번호 7, 인증·유효한 이메일, 닉네임 "카카오"로 답한다
                .andRespond(json("{\"id\":7,\"kakao_account\":{\"email\":\"k@kakao.com\",\"is_email_verified\":true,"
                        + "\"is_email_valid\":true,\"profile\":{\"nickname\":\"카카오\"}}}"));
        // 실행+확인: 카카오 사용자 정보를 가져오면
        assertThat(client.fetchProfile(SocialProvider.KAKAO, "code", REDIRECT, "s"))
                // 이메일을 쓰고 닉네임을 이름으로 써야 한다
                .isEqualTo(new SocialProfile(SocialProvider.KAKAO, "7", "k@kakao.com", "카카오"));
    }

    // [상황] 네이버 로그인 토큰을 받는다.
    // [기대] 네이버가 요구하는 state 값을 토큰 요청에 함께 보낸다.
    @Test
    @DisplayName("네이버 토큰 교환에는 state를 함께 보낸다")
    void naverSendsState() {
        // 준비: 네이버 토큰 교환 요청이 와야 하고
        server.expect(requestTo("https://nid.naver.com/oauth2.0/token"))
                // (도구) content().string(containsString(글자)) = 요청 본문에 그 글자가 들어 있어야 한다
                // 요청 본문에 state=s-1이 들어 있어야 하며
                .andExpect(content().string(org.hamcrest.Matchers.containsString("state=s-1")))
                // 시험용 토큰으로 답한다
                .andRespond(json("{\"access_token\":\"at-1\"}"));
        // 준비: 네이버 사용자 정보 요청에는
        server.expect(requestTo("https://openapi.naver.com/v1/nid/me"))
                // 번호·이메일·이름으로 답한다
                .andRespond(json("{\"response\":{\"id\":\"n1\",\"email\":\"n@naver.com\",\"name\":\"네이버\"}}"));
        // 실행+확인: state s-1로 사용자 정보를 가져오면 이메일이 n@naver.com이어야 한다(state가 빠졌다면 가짜 서버가 실패시킴)
        assertThat(client.fetchProfile(SocialProvider.NAVER, "code", REDIRECT, "s-1").email()).isEqualTo("n@naver.com");
    }

    // [상황] 깃허브가 200 응답 안에 오류(bad_verification_code)를 담아 보낸다.
    // [기대] 제공자 오류(PROVIDER_ERROR)로 처리한다.
    //        ※ 응답 코드: 200 = 정상 처리됨
    @Test
    @DisplayName("토큰 교환이 200에 error를 실어 오면 PROVIDER_ERROR")
    void tokenErrorInBody() {
        // 준비: 깃허브 토큰 교환 요청에
        server.expect(requestTo("https://github.com/login/oauth/access_token"))
                // 200 응답이지만 본문에 오류(bad_verification_code)를 담아 답한다
                .andRespond(json("{\"error\":\"bad_verification_code\"}"));
        // (도구) assertThatThrownBy(() -> 코드) = 그 코드를 돌리면 예외가 나야 통과. isInstanceOf = 예외 종류, extracting = 예외에서 값을 꺼내 검사
        // 실행+확인: 사용자 정보를 가져오면
        assertThatThrownBy(() -> client.fetchProfile(SocialProvider.GITHUB, "code", REDIRECT, "s"))
                // 소셜 로그인 예외가 나야 하고
                .isInstanceOf(SocialLoginException.class)
                // 그 예외의 오류 종류를 꺼내면
                .extracting(e -> ((SocialLoginException) e).error())
                // PROVIDER_ERROR(제공자 오류)여야 한다
                .isEqualTo(SocialLoginError.PROVIDER_ERROR);
    }

    // 도우미: "토큰 교환 요청이 오면 테스트용 토큰을 준다"를 가짜 서버에 걸어 둔다.
    private void token(String url) {
        // (도구) method(POST) = POST 방식이어야 한다
        // 그 주소로 POST 요청이 와야 하고
        server.expect(requestTo(url)).andExpect(method(HttpMethod.POST))
                // 본문 형식이 폼(x-www-form-urlencoded)이어야 하며
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_FORM_URLENCODED))
                // 시험용 토큰 at-1로 답한다
                .andRespond(json("{\"access_token\":\"at-1\",\"token_type\":\"bearer\"}"));
    }

    // 테스트 도구: 이 JSON 글자로 200 응답을 만든다
    private static org.springframework.test.web.client.ResponseCreator json(String body) {
        // (도구) withSuccess(본문, 형식) = 200 성공 응답을 만든다
        return withSuccess(body, MediaType.APPLICATION_JSON);
    }
}
