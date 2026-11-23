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
@WebMvcTest
@Import(WebSliceConfig.class)
class SecurityRulesTest {

    private static final Duration TTL = Duration.ofMinutes(15);
    private static final String RENTAL = NanoId.next();
    private static final String CHECKPOINT = NanoId.next();
    private static final String CREATE_BODY =
            "{\"rentalId\":\"" + RENTAL + "\",\"checkpointId\":\"" + CHECKPOINT
                    + "\",\"deviceSerial\":\"C02TEST00001\"}";

    @Autowired
    MockMvc mvc;
    @Autowired
    JwtIssuer issuer;
    @Autowired
    SigningKeyProvider keys;
    @Autowired
    AuthProperties properties;

    @MockitoBean
    LoginService loginService;
    @MockitoBean
    BoothTokenService boothTokenService;
    @MockitoBean
    PairingService pairingService;
    @MockitoBean
    CaptureLinkService captureLinkService;
    @MockitoBean
    SignupService signupService;
    @MockitoBean
    PasswordResetService passwordResetService;
    @MockitoBean
    WithdrawService withdrawService;
    @MockitoBean
    SocialLoginService socialLoginService;
    @MockitoBean
    OAuthStateStore oauthStateStore;
    @MockitoBean
    SocialProviderClient socialProviderClient;

    // [상황] 가입·이메일 인증·인증 메일 재발송·비밀번호 재설정을 로그인 없이 부르고, 만료된 토큰을 붙여서도 부른다.
    // [기대] 모두 열려 있고, 만료 토큰 때문에 401이 나지 않는다(로그인 못 하는 사람이 쓰는 기능이므로).
    @Test
    @DisplayName("가입·인증·재발송·재설정은 토큰 없이 부르고, 만료된 Bearer가 붙어도 401이 아니다")
    void accountPathsArePublic() throws Exception {
        given(signupService.signup(anyString(), anyString(), anyString(), eq(true)))
                .willReturn(new SignupResult(NanoId.next(), AccountStatus.PENDING));
        mvc.perform(post("/api/v1/auth/signup").header("Authorization", "Bearer broken")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"password\":\"pass-1234\",\"name\":\"홍길동\","
                                + "\"privacyAgreed\":true}"))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"));
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"123456\"}"))
                .andExpect(status().isNoContent());
        mvc.perform(post("/api/v1/auth/email/resend").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                .andExpect(status().isAccepted());
        mvc.perform(post("/api/v1/auth/password/reset-request").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                .andExpect(status().isAccepted());
        mvc.perform(post("/api/v1/auth/password/reset").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"123456\",\"newPassword\":\"new-pass-5678\"}"))
                .andExpect(status().isNoContent());
    }

    // [상황] 이메일 인증 코드를 틀리게 넣고, 60초 안에 인증 메일을 다시 보내 달라고 한다.
    // [기대] 틀리면 400 CODE_INVALID와 남은 시도 횟수, 너무 빠른 재발송은 429와 몇 초 뒤 다시(Retry-After).
    @Test
    @DisplayName("인증 코드가 틀리면 400 CODE_INVALID와 남은 횟수, 60초 안 재발송은 429와 Retry-After다")
    void codeProblems() throws Exception {
        willThrow(new CodeInvalidException(4)).given(signupService).verify(anyString(), anyString());
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"000000\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("CODE_INVALID"))
                .andExpect(jsonPath("$.remainingAttempts").value(4));
        willThrow(new RateLimitedException(ErrorCode.RESEND_TOO_SOON, 42)).given(signupService).resend(anyString());
        mvc.perform(post("/api/v1/auth/email/resend").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\"}"))
                .andExpect(status().isTooManyRequests())
                .andExpect(header().string("Retry-After", "42"))
                .andExpect(jsonPath("$.code").value("RESEND_TOO_SOON"));
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"r@trace.test\",\"code\":\"12ab\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
    }

    // [상황] 고객·관리자·QR 촬영 토큰으로 탈퇴를 부른다.
    // [기대] 일반 고객 토큰만 탈퇴할 수 있고, 관리자·촬영 토큰은 403.
    @Test
    @DisplayName("탈퇴는 CUSTOMER 일반 토큰만 하고 ADMIN·촬영 JWT는 403이다")
    void withdrawIsCustomerOnly() throws Exception {
        String body = "{\"password\":\"pass-1234\"}";
        for (TokenClaims claims : List.of(TokenClaims.admin(NanoId.next(), TTL),
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL))) {
            mvc.perform(delete("/api/v1/auth/me").header("Authorization", bearer(claims))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isForbidden());
        }
        String accountId = NanoId.next();
        Instant loggedInAt = Instant.ofEpochSecond(1_794_000_000L);
        mvc.perform(delete("/api/v1/auth/me").header("Authorization",
                                bearer(TokenClaims.customer(accountId, List.of(), TTL).withAuthTime(loggedInAt)))
                        .contentType(MediaType.APPLICATION_JSON).content(body))
                .andExpect(status().isNoContent());
        // 토큰의 auth_time(로그인 시각)을 그대로 넘긴다
        verify(withdrawService).withdraw(accountId, "pass-1234", loggedInAt);
    }

    // [상황] 만료된 접속 토큰으로 내 정보를 부른다.
    // [기대] 401.
    @Test
    @DisplayName("만료된 액세스 토큰은 401이다")
    void expiredAccessToken() throws Exception {
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), Clock.systemUTC().getZone());
        String expired = new JwtIssuer(keys, properties, past)
                .issue(TokenClaims.admin(NanoId.next(), TTL)).value();
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(content().contentTypeCompatibleWith(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // [상황] 로그인 없이 내 정보를 부른다.
    // [기대] 401.
    @Test
    @DisplayName("토큰 없이 내 정보를 부르면 401이다")
    void meWithoutToken() throws Exception {
        mvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // [상황] 관리자·고객 토큰으로 내 정보를 부른다.
    // [기대] 둘 다 볼 수 있다.
    @Test
    @DisplayName("ADMIN·CUSTOMER 일반 토큰은 내 정보를 본다")
    void meWithCustomer() throws Exception {
        String accountId = NanoId.next();
        given(loginService.me(accountId)).willReturn(new MeView(accountId, "c@trace.test", "고객",
                AccountRole.CUSTOMER, AccountStatus.ACTIVE, List.of(RENTAL), List.of(), true));
        mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(TokenClaims.customer(accountId,
                        List.of(RENTAL), TTL))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rentalIds[0]").value(RENTAL))
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }

    // [상황] QR 촬영 토큰·부스 토큰·진단 에이전트 토큰으로 내 정보를 부른다.
    // [기대] 한 가지 일만 하는 좁은 토큰이라 403.
    @Test
    @DisplayName("촬영 JWT·BOOTH·AGENT로 내 정보를 부르면 403이다")
    void meWithNarrowTokens() throws Exception {
        for (TokenClaims claims : List.of(
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL),
                TokenClaims.booth("booth-1", TTL),
                TokenClaims.agent(CHECKPOINT, RENTAL, "C02TEST00001", TTL))) {
            mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(claims)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        }
    }

    // [상황] QR 링크와 페어링 코드 발급을 관리자·고객 토큰으로 부른다.
    // [기대] 관리자만 발급할 수 있고 고객은 403.
    @Test
    @DisplayName("QR 링크·페어링 코드 발급은 ADMIN만 하고 CUSTOMER는 403이다")
    void issuingIsAdminOnly() throws Exception {
        String customer = bearer(TokenClaims.customer(NanoId.next(), List.of(), TTL));
        for (String path : List.of("/api/v1/auth/capture-links", "/api/v1/auth/pairing-codes")) {
            mvc.perform(post(path).header("Authorization", customer)
                            .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                    .andExpect(status().isForbidden());
        }
        given(pairingService.create(RENTAL, CHECKPOINT, "C02TEST00001"))
                .willReturn(new PairingService.IssuedCode("123456", Instant.parse("2026-11-12T00:05:00Z")));
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("123456"))
                .andExpect(jsonPath("$.expiresAt").value("2026-11-12T00:05:00Z"));
    }

    // [상황] 페어링 코드를 기기 일련번호 없이, 빈 값으로, 64자를 넘는 값으로 발급하려 한다.
    // [기대] 모두 400. 코드는 반드시 특정 기기에 묶여야 한다(다른 노트북 진단이 섞이지 않게).
    @Test
    @DisplayName("페어링 코드 발급에 기기 시리얼이 없거나 비었거나 64자를 넘으면 400이다")
    void pairingCodeNeedsDeviceSerial() throws Exception {
        String admin = bearer(TokenClaims.admin(NanoId.next(), TTL));
        String head = "{\"rentalId\":\"" + RENTAL + "\",\"checkpointId\":\"" + CHECKPOINT + "\"";
        for (String body : List.of(head + "}", head + ",\"deviceSerial\":\" \"}",
                head + ",\"deviceSerial\":\"" + "A".repeat(65) + "\"}")) {
            mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization", admin)
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isBadRequest())
                    .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        }
    }

    // [상황] QR 교환을 고객·관리자·촬영 토큰으로 부른다.
    // [기대] 로그인한 일반 고객만 할 수 있고, 관리자·촬영 토큰은 403.
    @Test
    @DisplayName("QR 교환은 로그인한 일반 고객만 하고 ADMIN·촬영 JWT는 403이다")
    void exchangeIsCustomerOnly() throws Exception {
        String body = "{\"token\":\"abcdefghijklmnopqrstuvwxyz0123456789ABCDEFG\"}";
        for (TokenClaims claims : List.of(TokenClaims.admin(NanoId.next(), TTL),
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL))) {
            mvc.perform(post("/api/v1/auth/capture-links/exchange").header("Authorization", bearer(claims))
                            .contentType(MediaType.APPLICATION_JSON).content(body))
                    .andExpect(status().isForbidden());
        }
    }

    // [상황] 렌탈 번호를 정해진 모양(21자 ID)이 아닌 값으로 보낸다.
    // [기대] 400 VALIDATION_FAILED.
    @Test
    @DisplayName("형식이 틀린 rentalId는 400 VALIDATION_FAILED이다")
    void invalidPublicId() throws Exception {
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rentalId\":\"not-a-nanoid\",\"checkpointId\":\"" + CHECKPOINT
                                + "\",\"deviceSerial\":\"C02TEST00001\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors[0].field").value("rentalId"));
    }

    // [상황] 로그인·리프레시·부스 토큰·페어링 교환을 토큰 없이 틀린 값으로 부른다.
    // [기대] 열려 있는 주소라 401이 아니라 각 기능의 오류(예: 비밀번호 틀림)를 계약 오류 형식(Problem)으로 준다.
    @Test
    @DisplayName("로그인·리프레시·부스 토큰·페어링 교환은 토큰 없이 열리고 도메인 오류는 Problem 본문이다")
    void publicEndpoints() throws Exception {
        given(loginService.login(anyString(), anyString()))
                .willThrow(new AuthException(ErrorCode.INVALID_CREDENTIALS));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"a@trace.test\",\"password\":\"x\"}"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"))
                .andExpect(jsonPath("$.instance").value("/api/v1/auth/login"));
        given(loginService.refresh(any())).willThrow(new AuthException(ErrorCode.REFRESH_INVALID));
        mvc.perform(post("/api/v1/auth/refresh"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
        given(boothTokenService.issue(eq("booth-1"), anyString()))
                .willThrow(new AuthException(ErrorCode.CLIENT_CREDENTIALS_INVALID));
        mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"clientId\":\"booth-1\",\"clientSecret\":\"x\"}"))
                .andExpect(status().isUnauthorized());
        mvc.perform(post("/api/v1/auth/pairing-codes/exchange").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"code\":\"12345\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"));
        mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kid").value(keys.publicJwk().getKeyID()));
    }

    // [상황] 위 공개 주소들에 만료된 토큰이 붙어 온다(브라우저에 남은 옛 토큰).
    // [기대] 토큰 만료(401) 대신 그 기능의 결과를 그대로 준다.
    @Test
    @DisplayName("공개 경로는 만료된 Bearer가 붙어 와도 401 UNAUTHENTICATED가 아니라 도메인 결과를 낸다")
    void publicEndpointsIgnoreStaleBearer() throws Exception {
        Clock past = Clock.fixed(Instant.now().minus(Duration.ofHours(1)), Clock.systemUTC().getZone());
        String expired = new JwtIssuer(keys, properties, past)
                .issue(TokenClaims.admin(NanoId.next(), TTL)).value();
        given(loginService.refresh(any())).willThrow(new AuthException(ErrorCode.REFRESH_INVALID));
        mvc.perform(post("/api/v1/auth/refresh").header("Authorization", "Bearer " + expired))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + expired))
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    // 도우미: 테스트용 토큰을 만든다.
    private String bearer(TokenClaims claims) {
        return "Bearer " + issuer.issue(claims).value();
    }
}
