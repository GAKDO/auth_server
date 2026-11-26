// 이 파일이 확인하는 것: auth-server의 주소별 보안 규칙(누가 어떤 기능을 쓸 수 있나)과 오류 응답 모양.
// DB 없이 컨트롤러만 띄우고 테스트용 토큰을 붙여 부른다.

package com.gakdo.trace.auth.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willThrow;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.WebMvcTest;
import org.springframework.context.annotation.Import;
import org.springframework.http.MediaType;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.gakdo.trace.auth.account.application.LoginService;
import com.gakdo.trace.auth.account.application.MeView;
import com.gakdo.trace.auth.account.application.PasswordResetService;
import com.gakdo.trace.auth.account.application.SignupResult;
import com.gakdo.trace.auth.account.application.SignupService;
import com.gakdo.trace.auth.account.application.WithdrawService;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.booth.application.BoothTokenService;
import com.gakdo.trace.auth.capture.application.CaptureLinkService;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.RateLimitedException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.pairing.application.PairingService;
import com.gakdo.trace.auth.social.application.OAuthStateStore;
import com.gakdo.trace.auth.social.application.SocialLoginService;
import com.gakdo.trace.auth.social.application.SocialProviderClient;
import com.gakdo.trace.auth.support.WebSliceConfig;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.domain.TokenClaims;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

/** 역할별 접근 규칙(contracts x-trace-access)과 401·403 Problem 본문. DB 없이 실제 SecurityConfig로 확인한다. */
// ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨), 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
// (도구) @WebMvcTest = 서버 전체 대신 컨트롤러들만 띄우는 가벼운 API 테스트(DB 없음)
@WebMvcTest
// 운영과 같은 보안 규칙(SecurityConfig)과 토큰 발급기를 함께 띄운다 = 실제 접근 규칙을 시험
@Import(WebSliceConfig.class)
class SecurityRulesTest {

    // 시험용 토큰 유효 시간 15분
    private static final Duration TTL = Duration.ofMinutes(15);
    // 시험용 렌탈 ID(실행마다 새로)
    private static final String RENTAL = NanoId.next();
    // 시험용 시점 ID
    private static final String CHECKPOINT = NanoId.next();
    // QR 링크·페어링 코드 발급 요청 본문(렌탈·시점·기기 일련번호)
    private static final String CREATE_BODY =
            "{\"rentalId\":\"" + RENTAL + "\",\"checkpointId\":\"" + CHECKPOINT
                    + "\",\"deviceSerial\":\"C02TEST00001\"}";

    // (도구) @Autowired = 스프링이 만들어 둔 부품을 넣어 준다. MockMvc = 진짜 네트워크 없이 HTTP 요청을 흉내 내는 도구
    @Autowired
    MockMvc mvc;
    // 시험용 토큰을 만드는 진짜 발급기
    @Autowired
    JwtIssuer issuer;
    // 서명 열쇠(만료 토큰을 따로 만들 때 쓴다)
    @Autowired
    SigningKeyProvider keys;
    // 인증 설정 값
    @Autowired
    AuthProperties properties;

    // (도구) @MockitoBean = 진짜 대신 가짜(목)를 스프링에 끼워 넣는다. 아래 서비스들은 모두 가짜로 두고 "문을 통과하는지"만 본다
    // 로그인 서비스(가짜)
    @MockitoBean
    LoginService loginService;
    // 부스 토큰 서비스(가짜)
    @MockitoBean
    BoothTokenService boothTokenService;
    // 페어링 서비스(가짜)
    @MockitoBean
    PairingService pairingService;
    // QR 링크 서비스(가짜)
    @MockitoBean
    CaptureLinkService captureLinkService;
    // 가입 서비스(가짜)
    @MockitoBean
    SignupService signupService;
    // 비밀번호 재설정 서비스(가짜)
    @MockitoBean
    PasswordResetService passwordResetService;
    // 탈퇴 서비스(가짜)
    @MockitoBean
    WithdrawService withdrawService;
    // 소셜 로그인 서비스(가짜)
    @MockitoBean
    SocialLoginService socialLoginService;
    // 소셜 로그인 state 저장소(가짜)
    @MockitoBean
    OAuthStateStore oauthStateStore;
    // 소셜 제공자 클라이언트(가짜)
    @MockitoBean
    SocialProviderClient socialProviderClient;

    // [상황] 가입·이메일 인증·인증 메일 재발송·비밀번호 재설정을 로그인 없이 부르고, 만료된 토큰을 붙여서도 부른다.
    // [기대] 모두 열려 있고, 만료 토큰 때문에 401이 나지 않는다(로그인 못 하는 사람이 쓰는 기능이므로).
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("가입·인증·재발송·재설정은 토큰 없이 부르고, 만료된 Bearer가 붙어도 401이 아니다")
    void accountPathsArePublic() throws Exception {
        // (도구) given(가짜.메서드(조건)).willReturn(결과) = when().thenReturn()과 같은 뜻. anyString() = 아무 글자나, eq(값) = 그 값일 때
        // 준비: 가입하면 "인증 대기(PENDING)" 결과를 돌려주게 한다
        given(signupService.signup(anyString(), anyString(), anyString(), eq(true)))
                .willReturn(new SignupResult(NanoId.next(), AccountStatus.PENDING));
        // (도구) perform(post(주소)...) = POST 요청을 보낸다. header = 머리말 붙이기. andExpect(...) = 응답 검사
        // 실행: 깨진 토큰("broken")을 붙인 채 가입을 요청한다
        mvc.perform(post("/api/v1/auth/signup").header("Authorization", "Bearer broken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"password\":\"pass-1234\",\"name\":\"홍길동\","
                                + "\"privacyAgreed\":true}"))
                // (도구) status().isCreated() = 응답 코드가 201(새로 만들어짐)인지 본다
                // 확인: 깨진 토큰이 붙어도 201로 가입돼야 한다
                .andExpect(status().isCreated())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸 값을 꺼낸다
                // 확인: 상태가 PENDING이어야 한다
                .andExpect(jsonPath("$.status").value("PENDING"));
        // 실행: 토큰 없이 이메일 인증을 요청한다
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"123456\"}"))
                // (도구) status().isNoContent() = 응답 코드가 204(성공, 내용 없음)인지 본다
                // 확인: 204여야 한다
                .andExpect(status().isNoContent());
        // 실행: 토큰 없이 인증 메일 재발송을 요청한다
        mvc.perform(post("/api/v1/auth/email/resend").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                // (도구) status().isAccepted() = 응답 코드가 202(받아들임)인지 본다
                // 확인: 202여야 한다
                .andExpect(status().isAccepted());
        // 실행: 토큰 없이 비밀번호 재설정 코드를 요청한다
        mvc.perform(post("/api/v1/auth/password/reset-request").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                // 확인: 202여야 한다
                .andExpect(status().isAccepted());
        // 실행: 토큰 없이 새 비밀번호로 재설정한다
        mvc.perform(post("/api/v1/auth/password/reset").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"123456\",\"newPassword\":\"new-pass-5678\"}"))
                // 확인: 204여야 한다
                .andExpect(status().isNoContent());
    }

    // [상황] 이메일 인증 코드를 틀리게 넣고, 60초 안에 인증 메일을 다시 보내 달라고 한다.
    // [기대] 틀리면 400 CODE_INVALID와 남은 시도 횟수, 너무 빠른 재발송은 429와 몇 초 뒤 다시(Retry-After).
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음, 429 = 요청이 너무 잦아 잠시 막음
    @Test
    @DisplayName("인증 코드가 틀리면 400 CODE_INVALID와 남은 횟수, 60초 안 재발송은 429와 Retry-After다")
    void codeProblems() throws Exception {
        // (도구) willThrow(예외).given(가짜).메서드(...) = 그 메서드가 불리면 예외를 던지게 한다(void 메서드용 순서)
        // 준비: 인증하면 "코드 틀림, 남은 시도 4번" 예외가 나게 한다
        willThrow(new CodeInvalidException(4)).given(signupService).verify(anyString(), anyString());
        // 실행: 틀린 코드로 인증을 요청한다
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"000000\"}"))
                // (도구) status().isBadRequest() = 응답 코드가 400인지 본다
                // 확인: 400이어야 한다
                .andExpect(status().isBadRequest())
                // 확인: 오류 코드가 CODE_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("CODE_INVALID"))
                // 확인: 남은 시도 횟수 4가 응답에 실려야 한다
                .andExpect(jsonPath("$.remainingAttempts").value(4));
        // 준비: 재발송하면 "너무 빠름, 42초 뒤" 예외가 나게 한다
        willThrow(new RateLimitedException(ErrorCode.RESEND_TOO_SOON, 42)).given(signupService).resend(anyString());
        // 실행: 재발송을 요청한다
        mvc.perform(post("/api/v1/auth/email/resend").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                // (도구) status().isTooManyRequests() = 응답 코드가 429(너무 잦음)인지 본다
                // 확인: 429여야 한다
                .andExpect(status().isTooManyRequests())
                // (도구) header().string(이름, 값) = 응답 머리말이 그 값이어야 통과
                // 확인: Retry-After 머리말로 42초 뒤에 다시 하라고 알려야 한다
                .andExpect(header().string("Retry-After", "42"))
                // 확인: 오류 코드가 RESEND_TOO_SOON이어야 한다
                .andExpect(jsonPath("$.code").value("RESEND_TOO_SOON"));
        // 실행: 숫자 6자리가 아닌 코드("12ab")로 인증을 요청한다
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"12ab\"}"))
                // 확인: 400이어야 한다
                .andExpect(status().isBadRequest())
                // 확인: 형식 오류라 VALIDATION_FAILED여야 한다
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    // [상황] 고객·관리자·QR 촬영 토큰으로 탈퇴를 부른다.
    // [기대] 일반 고객 토큰만 탈퇴할 수 있고, 관리자·촬영 토큰은 403.
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("탈퇴는 CUSTOMER 일반 토큰만 하고 ADMIN·촬영 JWT는 403이다")
    void withdrawIsCustomerOnly() throws Exception {
        // 준비: 탈퇴 요청 본문(비밀번호)
        String body = "{\"password\":\"pass-1234\"}";
        // 관리자 토큰과 QR 촬영 토큰을 차례로
        for (TokenClaims claims : List.of(TokenClaims.admin(NanoId.next(), TTL),
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL))) {
            // (도구) delete(주소) = DELETE 요청
            // 실행: 그 토큰으로 탈퇴를 요청한다
            mvc.perform(delete("/api/v1/auth/me").header("Authorization", bearer(claims))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    // (도구) status().isForbidden() = 응답 코드가 403(권한 없음)인지 본다
                    // 확인: 403이어야 한다
                    .andExpect(status().isForbidden());
        }
        // 준비: 고객 계정 ID
        String accountId = NanoId.next();
        // 준비: 토큰에 넣을 로그인 시각
        Instant loggedInAt = Instant.ofEpochSecond(1_794_000_000L);
        // 실행: 로그인 시각이 담긴 일반 고객 토큰으로 탈퇴를 요청한다
        mvc.perform(delete("/api/v1/auth/me").header("Authorization",
                                bearer(TokenClaims.customer(accountId, List.of(), TTL).withAuthTime(loggedInAt)))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                // 확인: 204여야 한다
                .andExpect(status().isNoContent());
        // 토큰의 auth_time(로그인 시각)을 그대로 넘긴다
        // (도구) verify(가짜).메서드(값...) = 그 값들로 (한 번) 불렸는지 확인
        // 확인: 탈퇴 서비스에 계정 ID·비밀번호·로그인 시각이 그대로 넘어갔어야 한다
        verify(withdrawService).withdraw(accountId, "pass-1234", loggedInAt);
    }

    // [상황] 만료된 접속 토큰으로 내 정보를 부른다.
    // [기대] 401.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("만료된 액세스 토큰은 401이다")
    void expiredAccessToken() throws Exception {
        // 준비: 1시간 전을 가리키는 시계를 만든다
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), Clock.systemUTC().getZone());
        // 준비: 그 시계로 15분짜리 관리자 토큰을 만든다 = 이미 만료된 토큰
        String expired = new JwtIssuer(keys, properties, past)
                .issue(TokenClaims.admin(NanoId.next(), TTL)).value();
        // 실행: 만료된 토큰으로 내 정보를 부른다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expired))
                // (도구) status().isUnauthorized() = 응답 코드가 401인지 본다
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized())
                // (도구) content().contentTypeCompatibleWith(형식) = 응답 본문 형식이 그것이어야 통과
                // 확인: 오류 본문이 계약 형식(application/problem+json)이어야 한다
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                // 확인: 오류 코드가 UNAUTHENTICATED여야 한다
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // [상황] 로그인 없이 내 정보를 부른다.
    // [기대] 401.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("토큰 없이 내 정보를 부르면 401이다")
    void meWithoutToken() throws Exception {
        // 실행: 토큰 없이 내 정보를 부른다
        mvc.perform(get("/api/v1/auth/me"))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 UNAUTHENTICATED여야 한다
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // [상황] 관리자·고객 토큰으로 내 정보를 부른다.
    // [기대] 둘 다 볼 수 있다.
    @Test
    @DisplayName("ADMIN·CUSTOMER 일반 토큰은 내 정보를 본다")
    void meWithCustomer() throws Exception {
        // 준비: 고객 계정 ID
        String accountId = NanoId.next();
        // 준비: 내 정보를 물으면 렌탈 하나를 가진 고객 정보를 돌려주게 한다
        given(loginService.me(accountId)).willReturn(new MeView(accountId, "c@trace.test", "고객",
                AccountRole.CUSTOMER, AccountStatus.ACTIVE, List.of(RENTAL), List.of(), true));
        // 실행: 일반 고객 토큰으로 내 정보를 부른다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(TokenClaims.customer(accountId,
                        List.of(RENTAL), TTL))))
                // (도구) status().isOk() = 응답 코드가 200인지 본다
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 렌탈 목록 첫 번째가 그 렌탈이어야 한다
                .andExpect(jsonPath("$.rentalIds[0]").value(RENTAL))
                // 확인: 역할이 CUSTOMER여야 한다
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }

    // [상황] QR 촬영 토큰·부스 토큰·진단 에이전트 토큰으로 내 정보를 부른다.
    // [기대] 한 가지 일만 하는 좁은 토큰이라 403.
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("촬영 JWT·BOOTH·AGENT로 내 정보를 부르면 403이다")
    void meWithNarrowTokens() throws Exception {
        // 촬영 토큰·부스 토큰·에이전트 토큰을 차례로
        for (TokenClaims claims : List.of(
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL),
                TokenClaims.booth("booth-1", TTL),
                TokenClaims.agent(CHECKPOINT, RENTAL, "C02TEST00001", TTL))) {
            // 실행: 그 토큰으로 내 정보를 부른다
            mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(claims)))
                    // 확인: 403이어야 한다
                    .andExpect(status().isForbidden())
                    // 확인: 오류 코드가 FORBIDDEN이어야 한다
                    .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        }
    }

    // [상황] QR 링크와 페어링 코드 발급을 관리자·고객 토큰으로 부른다.
    // [기대] 관리자만 발급할 수 있고 고객은 403.
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("QR 링크·페어링 코드 발급은 ADMIN만 하고 CUSTOMER는 403이다")
    void issuingIsAdminOnly() throws Exception {
        // 준비: 일반 고객 토큰
        String customer = bearer(TokenClaims.customer(NanoId.next(), List.of(), TTL));
        // QR 링크 발급·페어링 코드 발급 주소를 차례로
        for (String path : List.of("/api/v1/auth/capture-links", "/api/v1/auth/pairing-codes")) {
            // 실행: 고객 토큰으로 발급을 요청한다
            mvc.perform(post(path).header("Authorization", customer)
                            .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                    // 확인: 403이어야 한다
                    .andExpect(status().isForbidden());
        }
        // 준비: 페어링 코드를 만들면 123456과 만료 시각을 돌려주게 한다
        given(pairingService.create(RENTAL, CHECKPOINT, "C02TEST00001"))
                .willReturn(new PairingService.IssuedCode("123456", Instant.parse("2026-11-12T00:05:00Z")));
        // 실행: 관리자 토큰으로 페어링 코드 발급을 요청한다
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                // 확인: 201이어야 한다
                .andExpect(status().isCreated())
                // 확인: 코드가 123456이어야 한다
                .andExpect(jsonPath("$.code").value("123456"))
                // 확인: 만료 시각이 UTC로 그대로 실려야 한다
                .andExpect(jsonPath("$.expiresAt").value("2026-11-12T00:05:00Z"));
    }

    // [상황] 페어링 코드를 기기 일련번호 없이, 빈 값으로, 64자를 넘는 값으로 발급하려 한다.
    // [기대] 모두 400. 코드는 반드시 특정 기기에 묶여야 한다(다른 노트북 진단이 섞이지 않게).
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음
    @Test
    @DisplayName("페어링 코드 발급에 기기 시리얼이 없거나 비었거나 64자를 넘으면 400이다")
    void pairingCodeNeedsDeviceSerial() throws Exception {
        // 준비: 관리자 토큰
        String admin = bearer(TokenClaims.admin(NanoId.next(), TTL));
        // 준비: 렌탈·시점까지만 있는 본문 앞부분
        String head = "{\"rentalId\":\"" + RENTAL + "\",\"checkpointId\":\"" + CHECKPOINT + "\"";
        // 일련번호 없음, 공백뿐, 65자 이 세 본문을 차례로
        for (String body : List.of(head + "}", head + ",\"deviceSerial\":\" \"}",
                head + ",\"deviceSerial\":\"" + "A".repeat(65) + "\"}")) {
            // 실행: 그 본문으로 페어링 코드 발급을 요청한다
            mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization", admin)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    // 확인: 400이어야 한다
                    .andExpect(status().isBadRequest())
                    // 확인: 오류 코드가 VALIDATION_FAILED여야 한다
                    .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        }
    }

    // [상황] QR 교환을 고객·관리자·촬영 토큰으로 부른다.
    // [기대] 로그인한 일반 고객만 할 수 있고, 관리자·촬영 토큰은 403.
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("QR 교환은 로그인한 일반 고객만 하고 ADMIN·촬영 JWT는 403이다")
    void exchangeIsCustomerOnly() throws Exception {
        // 준비: QR 교환 요청 본문(토큰 모양의 시험 값)
        String body = "{\"token\":\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\"}";
        // 관리자 토큰과 촬영 토큰을 차례로
        for (TokenClaims claims : List.of(TokenClaims.admin(NanoId.next(), TTL),
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL))) {
            // 실행: 그 토큰으로 QR 교환을 요청한다
            mvc.perform(post("/api/v1/auth/capture-links/exchange").header("Authorization", bearer(claims))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    // 확인: 403이어야 한다
                    .andExpect(status().isForbidden());
        }
    }

    // [상황] 렌탈 번호를 정해진 모양(21자 ID)이 아닌 값으로 보낸다.
    // [기대] 400 VALIDATION_FAILED.
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음
    @Test
    @DisplayName("형식이 틀린 rentalId는 400 VALIDATION_FAILED이다")
    void invalidPublicId() throws Exception {
        // 실행: 렌탈 ID를 "not-a-nanoid"로 넣어 관리자 토큰으로 페어링 코드 발급을 요청한다
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rentalId\":\"not-a-nanoid\",\"checkpointId\":\"" + CHECKPOINT
                                + "\",\"deviceSerial\":\"C02TEST00001\"}"))
                // 확인: 400이어야 한다
                .andExpect(status().isBadRequest())
                // 확인: 오류 코드가 VALIDATION_FAILED여야 한다
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                // 확인: 틀린 칸이 rentalId여야 한다
                .andExpect(jsonPath("$.errors[0].field").value("rentalId"));
    }

    // [상황] 로그인·리프레시·부스 토큰·페어링 교환을 토큰 없이 틀린 값으로 부른다.
    // [기대] 열려 있는 주소라 401이 아니라 각 기능의 오류(예: 비밀번호 틀림)를 계약 오류 형식(Problem)으로 준다.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("로그인·리프레시·부스 토큰·페어링 교환은 토큰 없이 열리고 도메인 오류는 Problem 본문이다")
    void publicEndpoints() throws Exception {
        // (도구) willThrow(예외) = 그 호출이 오면 예외를 던지게 한다
        // 준비: 로그인하면 "이메일·비밀번호 틀림" 예외가 나게 한다
        given(loginService.login(anyString(), anyString()))
                .willThrow(new AuthException(ErrorCode.INVALID_CREDENTIALS));
        // 실행: 토큰 없이 로그인을 요청한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@trace.test\",\"password\":\"x\"}"))
                // 확인: 401이어야 한다(로그인 실패)
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 INVALID_CREDENTIALS여야 한다 = 보안 문(UNAUTHENTICATED)이 아니라 기능의 오류
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                // 확인: Problem 본문의 instance에 요청 주소가 실려야 한다
                .andExpect(jsonPath("$.instance").value("/api/v1/auth/login"));
        // (도구) any() = 아무 값이나
        // 준비: 리프레시하면 REFRESH_INVALID 예외가 나게 한다
        given(loginService.refresh(any())).willThrow(new AuthException(ErrorCode.REFRESH_INVALID));
        // 실행: 토큰 없이 리프레시를 요청한다
        mvc.perform(post("/api/v1/auth/refresh"))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 REFRESH_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
        // 준비: booth-1의 부스 토큰을 발급하면 "자격 틀림" 예외가 나게 한다
        given(boothTokenService.issue(eq("booth-1"), anyString()))
                .willThrow(new AuthException(ErrorCode.CLIENT_CREDENTIALS_INVALID));
        // 실행: 토큰 없이 부스 토큰을 요청한다
        mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"booth-1\",\"clientSecret\":\"x\"}"))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized());
        // 실행: 5자리 코드로 페어링 교환을 요청한다
        mvc.perform(post("/api/v1/auth/pairing-codes/exchange").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"12345\"}"))
                // 확인: 400이어야 한다
                .andExpect(status().isBadRequest())
                // 확인: 형식 오류라 VALIDATION_FAILED여야 한다
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        // 실행: 토큰 없이 공개키 주소를 부른다
        mvc.perform(get("/.well-known/jwks.json"))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 열쇠 이름이 서버의 서명 열쇠 이름과 같아야 한다
                .andExpect(jsonPath("$.keys[0].kid").value(keys.publicJwk().getKeyID()));
    }

    // [상황] 위 공개 주소들에 만료된 토큰이 붙어 온다(브라우저에 남은 옛 토큰).
    // [기대] 토큰 만료(401) 대신 그 기능의 결과를 그대로 준다.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("공개 경로는 만료된 Bearer가 붙어 와도 401 UNAUTHENTICATED가 아니라 도메인 결과를 낸다")
    void publicEndpointsIgnoreStaleBearer() throws Exception {
        // 준비: 1시간 전을 가리키는 시계를 만든다
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), Clock.systemUTC().getZone());
        // 준비: 그 시계로 이미 만료된 관리자 토큰을 만든다
        String expired = new JwtIssuer(keys, properties, past)
                .issue(TokenClaims.admin(NanoId.next(), TTL)).value();
        // 준비: 리프레시하면 REFRESH_INVALID 예외가 나게 한다
        given(loginService.refresh(any())).willThrow(new AuthException(ErrorCode.REFRESH_INVALID));
        // 실행: 만료된 토큰을 붙인 채 리프레시를 요청한다
        mvc.perform(post("/api/v1/auth/refresh").header("Authorization", "Bearer " + expired))
                // 확인: 401이고
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 토큰 만료(UNAUTHENTICATED)가 아니라 기능 결과인 REFRESH_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
        // 실행: 비교용으로, 로그인이 필요한 내 정보 주소에 같은 만료 토큰을 붙여 부른다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expired))
                // 확인: 여기서는 UNAUTHENTICATED여야 한다 = 만료 토큰은 보호된 주소에서만 막힌다
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // 도우미: 테스트용 토큰을 만든다.
    private String bearer(TokenClaims claims) {
        // 그 내용으로 토큰을 발급해 "Bearer 토큰" 머리말 값으로 돌려준다
        return "Bearer " + issuer.issue(claims).value();
    }
}
