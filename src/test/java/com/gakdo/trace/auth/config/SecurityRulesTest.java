package com.gakdo.trace.auth.config;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.BDDMockito.given;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
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
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.booth.application.BoothTokenService;
import com.gakdo.trace.auth.capture.application.CaptureLinkService;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.pairing.application.PairingService;
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
            "{\"rentalId\":\"" + RENTAL + "\",\"checkpointId\":\"" + CHECKPOINT + "\"}";

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

    @Test
    @DisplayName("토큰 없이 내 정보를 부르면 401이다")
    void meWithoutToken() throws Exception {
        mvc.perform(get("/api/v1/auth/me"))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("UNAUTHENTICATED"));
    }

    @Test
    @DisplayName("ADMIN·CUSTOMER 일반 토큰은 내 정보를 본다")
    void meWithCustomer() throws Exception {
        String accountId = NanoId.next();
        given(loginService.me(accountId)).willReturn(new MeView(accountId, "c@trace.test", "고객",
                AccountRole.CUSTOMER, AccountStatus.ACTIVE, List.of(RENTAL)));
        mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(TokenClaims.customer(accountId,
                        List.of(RENTAL), TTL))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rentalIds[0]").value(RENTAL))
                .andExpect(jsonPath("$.role").value("CUSTOMER"));
    }

    @Test
    @DisplayName("촬영 JWT·BOOTH·AGENT로 내 정보를 부르면 403이다")
    void meWithNarrowTokens() throws Exception {
        for (TokenClaims claims : List.of(
                TokenClaims.capture(NanoId.next(), CHECKPOINT, RENTAL, TTL),
                TokenClaims.booth("booth-1", TTL),
                TokenClaims.agent(CHECKPOINT, RENTAL, TTL))) {
            mvc.perform(get("/api/v1/auth/me").header("Authorization", bearer(claims)))
                    .andExpect(status().isForbidden())
                    .andExpect(jsonPath("$.code").value("FORBIDDEN"));
        }
    }

    @Test
    @DisplayName("QR 링크·페어링 코드 발급은 ADMIN만 하고 CUSTOMER는 403이다")
    void issuingIsAdminOnly() throws Exception {
        String customer = bearer(TokenClaims.customer(NanoId.next(), List.of(), TTL));
        for (String path : List.of("/api/v1/auth/capture-links", "/api/v1/auth/pairing-codes")) {
            mvc.perform(post(path).header("Authorization", customer)
                            .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                    .andExpect(status().isForbidden());
        }
        given(pairingService.create(RENTAL, CHECKPOINT))
                .willReturn(new PairingService.IssuedCode("123456", Instant.parse("2026-11-12T00:05:00Z")));
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON).content(CREATE_BODY))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").value("123456"))
                .andExpect(jsonPath("$.expiresAt").value("2026-11-12T00:05:00Z"));
    }

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

    @Test
    @DisplayName("형식이 틀린 rentalId는 400 VALIDATION_FAILED이다")
    void invalidPublicId() throws Exception {
        mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization",
                                bearer(TokenClaims.admin(NanoId.next(), TTL)))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"rentalId\":\"not-a-nanoid\",\"checkpointId\":\"" + CHECKPOINT + "\"}"))
                .andExpect(status().isBadRequest())
                .andExpect(jsonPath("$.code").value("VALIDATION_FAILED"))
                .andExpect(jsonPath("$.errors[0].field").value("rentalId"));
    }

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

    private String bearer(TokenClaims claims) {
        return "Bearer " + issuer.issue(claims).value();
    }
}
