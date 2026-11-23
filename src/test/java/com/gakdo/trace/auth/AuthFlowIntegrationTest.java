// 이 파일이 확인하는 것: 요구사항 AU1(로그인·토큰 발급) 전체 흐름을 진짜 DB(PostgreSQL)·Redis로 확인.
// TRACE의 토큰 종류: 관리자·고객 로그인 토큰, 부스 토큰(BOOTH), 진단 에이전트 토큰(AGENT, 페어링 코드로 받음),
// 촬영 JWT(고객이 QR을 찍으면 받는, 한 시점에만 쓰는 토큰). 비밀번호·부스 비밀값은 실행할 때마다 새로 만든다.
// Docker나 로컬 테스트 DB가 없으면 건너뛴다.

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
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
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
class AuthFlowIntegrationTest extends IntegrationTestBase {

    // 비밀번호 모양의 문자열을 커밋에 두지 않으려고(gitleaks) 실행할 때마다 만든다
    private static final String ADMIN_PASSWORD = NanoId.next();
    // 같은 DB로 다시 돌려도 겹치지 않게 실행마다 새 관리자·부스를 만든다(초기 데이터는 없을 때만 생성)
    private static final String ADMIN_EMAIL = "admin-" + NanoId.next().toLowerCase() + "@trace.test";
    private static final String BOOTH_ID = "booth-" + NanoId.next();
    private static final String BOOTH_SECRET = NanoId.next();
    private static final String PASSWORD = NanoId.next();

    @DynamicPropertySource
    static void initialData(DynamicPropertyRegistry registry) {
        registry.add("trace.auth.initial-admin.email", () -> ADMIN_EMAIL);
        registry.add("trace.auth.initial-admin.password", () -> ADMIN_PASSWORD);
        registry.add("trace.auth.initial-booth.client-id", () -> BOOTH_ID);
        registry.add("trace.auth.initial-booth.client-secret", () -> BOOTH_SECRET);
        registry.add("trace.auth.web-public-url", () -> "https://web.trace.test");
    }

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

    // [상황] 서버가 처음 켜질 때 초기 데이터로 관리자 계정이 만들어지고, 그 계정으로 로그인한다.
    // [기대] 접속 토큰(JWT)과 다시 받기용 리프레시 쿠키를 받는다.
    @Test
    @DisplayName("관리자 계정은 초기 데이터로 만들고 로그인하면 액세스 JWT와 리프레시 쿠키를 받는다")
    void adminLogin() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", ADMIN_EMAIL.toUpperCase(), "password", ADMIN_PASSWORD))))
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

    // [상황] 리프레시 쿠키로 접속 토큰을 다시 받고, 이미 한 번 쓴 리프레시와 로그아웃한 리프레시로 또 시도한다.
    // [기대] 다시 받기는 되고 리프레시도 새것으로 바뀐다. 쓴 것·로그아웃한 것은 401(도난 토큰 재사용 차단).
    @Test
    @DisplayName("리프레시로 다시 발급되고, 쓴 리프레시와 로그아웃한 리프레시는 401이다")
    void refreshRotationAndLogout() throws Exception {
        MvcResult login = login(ADMIN_EMAIL, ADMIN_PASSWORD);
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

    // [상황] 비밀번호를 틀리고, 이메일 인증을 아직 안 한 고객으로 로그인한다.
    // [기대] 틀린 비밀번호는 401, 인증 전 고객은 403.
    @Test
    @DisplayName("틀린 비밀번호는 401이고 인증 전 고객은 403이다")
    void loginFailures() throws Exception {
        Account pending = customer(AccountStatus.PENDING);
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", NanoId.next()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", PASSWORD))))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));
    }

    // [상황] 관리자가 진단 에이전트용 6자리 페어링 코드를 발급하고, 에이전트가 그 코드를 토큰으로 바꾼다.
    // [기대] DB에는 코드 원문 없이 SHA-256 해시만 저장된다. 한 번만 AGENT 토큰으로 바뀌고, 5분이 지나면 만료된다.
    @Test
    @DisplayName("페어링 코드는 SHA-256 해시만 저장하고 한 번만 AGENT JWT로 바뀌며 5분 뒤 만료된다")
    void pairingCode() throws Exception {
        String admin = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
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
                .andExpect(jsonPath("$.deviceSerial").value("C02TEST00001"))
                .andReturn();
        Jwt agent = jwtDecoder.decode(token(exchanged));
        assertThat(agent.getClaimAsString("role")).isEqualTo("AGENT");
        assertThat(agent.getClaimAsString("scope")).isEqualTo(checkpointId);
        assertThat(agent.getClaimAsString("rentalId")).isEqualTo(rentalId);
        assertThat(agent.getClaimAsString("deviceSerial")).isEqualTo("C02TEST00001");

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

    // [상황] 부스(Jetson)가 부스 ID·비밀값으로 토큰을 요청한다. 틀린 비밀값으로도 해 본다.
    // [기대] 맞으면 BOOTH 토큰, 틀리면 401.
    @Test
    @DisplayName("부스 자격은 BOOTH JWT로 바뀌고 틀린 secret은 401이다")
    void boothToken() throws Exception {
        MvcResult ok = mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", BOOTH_ID, "clientSecret", BOOTH_SECRET))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.boothId").value(BOOTH_ID))
                .andExpect(jsonPath("$.expiresIn").value(3600))
                .andReturn();
        Jwt booth = jwtDecoder.decode(token(ok));
        assertThat(booth.getClaimAsString("role")).isEqualTo("BOOTH");
        assertThat(booth.getClaimAsString("scope")).isEqualTo(BOOTH_ID);

        mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", BOOTH_ID, "clientSecret", NanoId.next()))))
                .andExpect(status().isUnauthorized())
                .andExpect(jsonPath("$.code").value("CLIENT_CREDENTIALS_INVALID"));
    }

    // [상황] 관리자가 렌탈 시점용 QR 링크를 만들고, 고객이 QR을 찍어 교환한다. 다른 고객이 같은 렌탈 QR을 교환해 본다.
    // [기대] 고객은 그 시점에만 쓰는 촬영 JWT를 받고, 렌탈이 고객 계정에 연결된다.
    //        이미 다른 계정에 연결된 렌탈이면 409(남의 렌탈 가로채기 방지).
    @Test
    @DisplayName("QR 교환은 그 시점만 쓰는 촬영 JWT를 주고 렌탈을 계정에 연결하며, 다른 계정에 연결된 렌탈은 409이다")
    void captureLink() throws Exception {
        String admin = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
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

    // [상황] 발급한 토큰을 공개키 주소(JWKS)의 공개키로 검증한다.
    // [기대] 검증된다. 다른 서버들(gateway 등)은 이 공개키로 토큰을 확인한다.
    @Test
    @DisplayName("발급한 JWT는 JWKS 공개키로 검증된다")
    void jwks() throws Exception {
        String access = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
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
                        .content(body(Map.of("rentalId", rentalId, "checkpointId", checkpointId,
                                "deviceSerial", "C02TEST00001"))))
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
