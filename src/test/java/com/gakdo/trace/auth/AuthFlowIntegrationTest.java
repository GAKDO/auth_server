package com.gakdo.trace.auth;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.cookie;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.time.Clock;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.test.context.TestPropertySource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.support.IntegrationTestBase;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jose.crypto.RSASSAVerifier;

import jakarta.servlet.http.Cookie;

/** AU1 수용 기준을 실제 PostgreSQL(Flyway auth 스키마)·Redis로 확인한다. */
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
@TestPropertySource(properties = {
        "trace.auth.initial-admin.email=admin@trace.test",
        "trace.auth.initial-admin.password=admin-pass-1234",
        "trace.auth.initial-booth.client-id=booth-it",
        "trace.auth.initial-booth.client-secret=booth-secret-1234",
        "trace.auth.web-public-url=https://web.trace.test"})
class AuthFlowIntegrationTest extends IntegrationTestBase {

    private static final String PASSWORD = "customer-pass-1234";

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;
    @Autowired
    JwtDecoder jwtDecoder;
    @Autowired
    AccountRepository accounts;
    @Autowired
    PasswordEncoder passwordEncoder;
    @Autowired
    JdbcTemplate jdbc;

    @Test
    @DisplayName("관리자 계정은 초기 데이터로 만들고 로그인하면 액세스 JWT와 리프레시 쿠키를 받는다")
    void adminLogin() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content("{\"email\":\"ADMIN@trace.test\",\"password\":\"admin-pass-1234\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                .andExpect(jsonPath("$.expiresIn").value(900))
                .andExpect(cookie().httpOnly("trace_refresh", true))
                .andExpect(cookie().secure("trace_refresh", true))
                .andExpect(cookie().sameSite("trace_refresh", "Strict"))
                .andExpect(cookie().path("trace_refresh", "/api/v1/auth"))
                .andExpect(cookie().maxAge("trace_refresh", 604800));
    }

    @Test
    @DisplayName("리프레시로 다시 발급되고, 쓴 리프레시와 로그아웃한 리프레시는 401이다")
    void refreshRotationAndLogout() throws Exception {
        MvcResult login = login("admin@trace.test", "admin-pass-1234");
        Cookie first = login.getResponse().getCookie("trace_refresh");
        String access = token(login);

        MvcResult refreshed = mvc.perform(post("/api/v1/auth/refresh").cookie(first))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("ADMIN"))
                .andReturn();
        Cookie second = refreshed.getResponse().getCookie("trace_refresh");
        assertThat(second.getValue()).isNotEqualTo(first.getValue());

        mvc.perform(post("/api/v1/auth/refresh").cookie(first))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));

        mvc.perform(post("/api/v1/auth/logout").cookie(second).header("Authorization", "Bearer " + access))
                .andExpect(status().isNoContent())
                .andExpect(cookie().maxAge("trace_refresh", 0));
        mvc.perform(post("/api/v1/auth/refresh").cookie(second))
                .andExpect(status().isUnauthorized());
    }

    @Test
    @DisplayName("틀린 비밀번호는 401이고 인증 전 고객은 403이다")
    void loginFailures() throws Exception {
        Account pending = customer(AccountStatus.PENDING);
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", "wrong-pass-1234"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", PASSWORD))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));
    }

    @Test
    @DisplayName("페어링 코드는 SHA-256 해시만 저장하고 한 번만 AGENT JWT로 바뀌며 5분 뒤 만료된다")
    void pairingCode() throws Exception {
        String admin = token(login("admin@trace.test", "admin-pass-1234"));
        String rentalId = NanoId.next();
        String checkpointId = NanoId.next();

        String code = issuePairing(admin, rentalId, checkpointId);
        List<String> stored = jdbc.queryForList(
                "select code_hash from auth.pairing_code where checkpoint_id = ?", String.class, checkpointId);
        assertThat(stored).containsExactly(Sha256.hex(code)).noneMatch(h -> h.contains(code));

        MvcResult exchanged = mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", code))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(600))
                .andExpect(jsonPath("$.rentalId").value(rentalId))
                .andExpect(jsonPath("$.checkpointId").value(checkpointId))
                .andReturn();
        Jwt agent = jwtDecoder.decode(token(exchanged));
        assertThat(agent.getClaimAsString("role")).isEqualTo("AGENT");
        assertThat(agent.getClaimAsString("scope")).isEqualTo(checkpointId);
        assertThat(agent.getClaimAsString("rentalId")).isEqualTo(rentalId);

        mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", code))))
                .andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("PAIRING_CODE_EXPIRED"));

        String late = issuePairing(admin, rentalId, NanoId.next());
        jdbc.update("update auth.pairing_code set expires_at = now() - interval '1 second' where code_hash = ?",
                Sha256.hex(late));
        mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", late))))
                .andExpect(status().isGone());
    }

    @Test
    @DisplayName("부스 자격은 BOOTH JWT로 바뀌고 틀린 secret은 401이다")
    void boothToken() throws Exception {
        MvcResult ok = mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", "booth-it", "clientSecret", "booth-secret-1234"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.boothId").value("booth-it"))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andReturn();
        Jwt booth = jwtDecoder.decode(token(ok));
        assertThat(booth.getClaimAsString("role")).isEqualTo("BOOTH");
        assertThat(booth.getClaimAsString("scope")).isEqualTo("booth-it");

        mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", "booth-it", "clientSecret", "wrong"))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CLIENT_CREDENTIALS_INVALID"));
    }

    @Test
    @DisplayName("QR 교환은 그 시점만 쓰는 촬영 JWT를 주고 렌탈을 계정에 연결하며, 다른 계정에 연결된 렌탈은 409이다")
    void captureLink() throws Exception {
        String admin = token(login("admin@trace.test", "admin-pass-1234"));
        String rentalId = NanoId.next();
        String checkpointId = NanoId.next();
        Account owner = customer(AccountStatus.ACTIVE);
        String ownerToken = token(login(owner.getEmail(), PASSWORD));

        String qr = issueLink(admin, rentalId, checkpointId);
        assertThat(jdbc.queryForObject("select token_hash from auth.capture_link where checkpoint_id = ?",
                String.class, checkpointId)).isEqualTo(Sha256.hex(qr));

        MvcResult exchanged = exchangeLink(ownerToken, qr)
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.expiresIn").value(1800))
                .andExpect(jsonPath("$.rentalId").value(rentalId))
                .andReturn();
        String capture = token(exchanged);
        Jwt captureJwt = jwtDecoder.decode(capture);
        assertThat(captureJwt.getClaimAsString("role")).isEqualTo("CUSTOMER");
        assertThat(captureJwt.getClaimAsString("scope")).isEqualTo(checkpointId);
        assertThat(captureJwt.getSubject()).isEqualTo(owner.getPublicId());

        // 고객 JWT로 다른 시점에 접근하면 403: 촬영 JWT는 시점 하나만 들고, 일반 고객 경로도 막힌다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + capture))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        exchangeLink(ownerToken, qr).andExpect(status().isGone())
                .andExpect(jsonPath("$.code").value("CAPTURE_LINK_INVALID"));

        Jwt relogin = jwtDecoder.decode(token(login(owner.getEmail(), PASSWORD)));
        assertThat(relogin.getClaimAsStringList("rentals")).containsExactly(rentalId);
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token(login(owner.getEmail(),
                        PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.rentalIds[0]").value(rentalId))
                .andExpect(jsonPath("$.accountId").value(owner.getPublicId()));

        Account other = customer(AccountStatus.ACTIVE);
        String otherToken = token(login(other.getEmail(), PASSWORD));
        exchangeLink(otherToken, issueLink(admin, rentalId, NanoId.next()))
                .andExpect(status().isConflict())
                .andExpect(jsonPath("$.code").value("RENTAL_LINKED_TO_OTHER"));
    }

    @Test
    @DisplayName("발급한 JWT는 JWKS 공개키로 검증된다")
    void jwks() throws Exception {
        String access = token(login("admin@trace.test", "admin-pass-1234"));
        String body = mvc.perform(get("/.well-known/jwks.json"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                .andReturn().getResponse().getContentAsString();
        RSAKey key = (RSAKey) JWKSet.parse(body).getKeys().get(0);
        SignedJWT jwt = SignedJWT.parse(access);
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.getKeyID());
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();
        assertThat(key.isPrivate()).isFalse();
    }

    private Account customer(AccountStatus status) {
        String email = "c-" + NanoId.next().toLowerCase() + "@trace.test";
        return accounts.save(Account.customer(NanoId.next(), email, passwordEncoder.encode(PASSWORD), "고객",
                status, Clock.systemUTC().instant()));
    }

    private MvcResult login(String email, String password) throws Exception {
        return mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", email, "password", password))))
                .andExpect(status().isOk())
                .andReturn();
    }

    private String issuePairing(String admin, String rentalId, String checkpointId) throws Exception {
        MvcResult issued = mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("rentalId", rentalId, "checkpointId", checkpointId))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.code").isString())
                .andReturn();
        return read(issued).get("code").asText();
    }

    private String issueLink(String admin, String rentalId, String checkpointId) throws Exception {
        MvcResult issued = mvc.perform(post("/api/v1/auth/capture-links").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("rentalId", rentalId, "checkpointId", checkpointId))))
                .andExpect(status().isCreated())
                .andExpect(header().doesNotExist("Set-Cookie"))
                .andReturn();
        String url = read(issued).get("url").asText();
        assertThat(url).startsWith("https://web.trace.test/capture?t=");
        return url.substring(url.indexOf("t=") + 2);
    }

    private org.springframework.test.web.servlet.ResultActions exchangeLink(String customer, String qr)
            throws Exception {
        return mvc.perform(post("/api/v1/auth/capture-links/exchange").header("Authorization", "Bearer " + customer)
                .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("token", qr))));
    }

    private String token(MvcResult result) throws Exception {
        return read(result).get("accessToken").asText();
    }

    private JsonNode read(MvcResult result) throws Exception {
        return json.readTree(result.getResponse().getContentAsString());
    }

    private String body(Map<String, String> values) throws Exception {
        return json.writeValueAsString(values);
    }
}
