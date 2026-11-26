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

/**
 * AU1(로그인·토큰 발급) 수용 기준을 실제 PostgreSQL(Flyway auth 스키마)·Redis로 확인한다.
 *
 * <p>확인하는 흐름: 관리자 로그인 → 리프레시로 다시 받기·로그아웃 → 틀린 비밀번호·인증 전 고객 거절 →
 * 진단 에이전트 페어링 코드 → AGENT 토큰, 부스 자격 → BOOTH 토큰, 고객 QR → 촬영 토큰 →
 * 발급한 토큰을 JWKS 공개키로 검증.
 *
 * <p>실행 조건: 진짜 PostgreSQL·Redis가 필요하다(바탕 클래스 IntegrationTestBase).
 * GitHub Actions는 Docker(Testcontainers)로 띄우고, Docker가 없으면 {@code TRACE_IT_LOCAL=1}일 때 로컬 테스트 전용 DB
 * trace_it·Redis DB 15에 붙는다. 둘 다 없으면 이 클래스 전체를 건너뛴다(실패가 아님).
 */
// (도구) @AutoConfigureMockMvc = 서버 전체를 띄운 상태에서 MockMvc(가짜 HTTP 요청 도구)도 쓸 수 있게 한다. @EnabledIf = 진짜 DB를 쓸 수 있을 때만 돌린다
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class AuthFlowIntegrationTest extends IntegrationTestBase {

    // 비밀번호 모양의 문자열을 커밋에 두지 않으려고(gitleaks) 실행할 때마다 만든다
    private static final String ADMIN_PASSWORD = NanoId.next();
    // 같은 DB로 다시 돌려도 겹치지 않게 실행마다 새 관리자·부스를 만든다(초기 데이터는 없을 때만 생성)
    private static final String ADMIN_EMAIL = "admin-" + NanoId.next().toLowerCase() + "@trace.test";
    // 실행마다 새 부스 ID
    private static final String BOOTH_ID = "booth-" + NanoId.next();
    // 부스 비밀값도 실행마다 무작위로 만든다
    private static final String BOOTH_SECRET = NanoId.next();
    // 시험용 고객 비밀번호도 실행마다 무작위로 만든다
    private static final String PASSWORD = NanoId.next();

    // (도구) @DynamicPropertySource = 서버가 뜨기 전에 설정 값을 코드로 넣는다
    @DynamicPropertySource
    static void initialData(DynamicPropertyRegistry registry) {
        // 초기 관리자 이메일 설정
        registry.add("trace.auth.initial-admin.email", () -> ADMIN_EMAIL);
        // 초기 관리자 비밀번호 설정
        registry.add("trace.auth.initial-admin.password", () -> ADMIN_PASSWORD);
        // 초기 부스 ID 설정
        registry.add("trace.auth.initial-booth.client-id", () -> BOOTH_ID);
        // 초기 부스 비밀값 설정
        registry.add("trace.auth.initial-booth.client-secret", () -> BOOTH_SECRET);
        // QR 링크에 들어갈 웹 주소 설정
        registry.add("trace.auth.web-public-url", () -> "https://web.trace.test");
    }

    // (도구) @Autowired = 스프링이 만들어 둔 부품을 넣어 준다. MockMvc = 진짜 네트워크 없이 HTTP 요청을 흉내 내는 도구
    @Autowired
    MockMvc mvc;
    // 요청 본문 JSON을 만들고 응답을 읽는 도구
    @Autowired
    ObjectMapper json;
    // (도구) JwtDecoder = 토큰(JWT)의 서명을 확인하고 안의 내용(claim)을 꺼내는 도구
    @Autowired
    JwtDecoder jwtDecoder;
    // 계정 저장소(진짜 DB)
    @Autowired
    AccountRepository accounts;
    // 비밀번호 해시 도구(진짜)
    @Autowired
    PasswordEncoder passwordEncoder;
    // (도구) JdbcTemplate = SQL을 직접 실행해 DB 내용을 확인하는 도구
    @Autowired
    JdbcTemplate jdbc;

    // [상황] 서버가 처음 켜질 때 초기 데이터로 관리자 계정이 만들어지고, 그 계정으로 로그인한다.
    // [기대] 접속 토큰(JWT)과 다시 받기용 리프레시 쿠키를 받는다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("관리자 계정은 초기 데이터로 만들고 로그인하면 액세스 JWT와 리프레시 쿠키를 받는다")
    void adminLogin() throws Exception {
        // (도구) perform(post(주소).contentType(JSON).content(본문)) = JSON 본문을 담아 POST 요청을 보낸다. andExpect(...) = 응답 검사
        // 실행: 초기 관리자 이메일을 대문자로 바꿔 로그인한다(대소문자 무시 확인)
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", ADMIN_EMAIL.toUpperCase(), "password", ADMIN_PASSWORD))))
                // (도구) status().isOk() = 응답 코드가 200(정상)인지 본다
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸 값을 꺼낸다
                // 확인: 역할이 ADMIN이어야 한다
                .andExpect(jsonPath("$.role").value("ADMIN"))
                // 확인: 토큰 종류가 Bearer여야 한다
                .andExpect(jsonPath("$.tokenType").value("Bearer"))
                // 확인: 액세스 토큰 유효 시간이 900초(15분)여야 한다
                .andExpect(jsonPath("$.expiresIn").value(900))
                // (도구) cookie().xxx(이름, 값) = 응답 쿠키의 속성을 검사한다
                // 확인: 리프레시 쿠키는 스크립트가 못 읽어야 한다(HttpOnly)
                .andExpect(cookie().httpOnly("trace_refresh", true))
                // 확인: HTTPS에서만 보내져야 한다(Secure)
                .andExpect(cookie().secure("trace_refresh", true))
                // 확인: 다른 사이트 요청에는 보내지지 않아야 한다(SameSite=Strict)
                .andExpect(cookie().sameSite("trace_refresh", "Strict"))
                // 확인: 인증 주소에서만 보내져야 한다
                .andExpect(cookie().path("trace_refresh", "/api/v1/auth"))
                // 확인: 유지 기간이 604800초(7일)여야 한다
                .andExpect(cookie().maxAge("trace_refresh", 604800));
    }

    // [상황] 리프레시 쿠키로 접속 토큰을 다시 받고, 이미 한 번 쓴 리프레시와 로그아웃한 리프레시로 또 시도한다.
    // [기대] 다시 받기는 되고 리프레시도 새것으로 바뀐다. 쓴 것·로그아웃한 것은 401(도난 토큰 재사용 차단).
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("리프레시로 다시 발급되고, 쓴 리프레시와 로그아웃한 리프레시는 401이다")
    void refreshRotationAndLogout() throws Exception {
        // 준비: 관리자로 로그인해 응답을 받아 둔다
        MvcResult login = login(ADMIN_EMAIL, ADMIN_PASSWORD);
        // 첫 리프레시 쿠키를 꺼낸다
        Cookie first = login.getResponse().getCookie("trace_refresh");
        // 액세스 토큰을 꺼낸다(로그아웃 때 쓰려고)
        String access = token(login);

        // (도구) cookie(쿠키) = 요청에 쿠키를 함께 보낸다
        // 실행: 첫 리프레시 쿠키로 토큰을 다시 받는다
        MvcResult refreshed = mvc.perform(post("/api/v1/auth/refresh").cookie(first))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 역할이 ADMIN이어야 한다
                .andExpect(jsonPath("$.role").value("ADMIN"))
                // 응답을 꺼내 둔다
                .andReturn();
        // 새로 받은 리프레시 쿠키를 꺼낸다
        Cookie second = refreshed.getResponse().getCookie("trace_refresh");
        // (도구) assertThat(값).isNotEqualTo(값2) = 두 값이 달라야 통과
        // 확인: 리프레시가 새 값으로 바뀌어야 한다(한 번 쓰면 교체)
        assertThat(second.getValue()).isNotEqualTo(first.getValue());

        // 실행: 이미 쓴 첫 리프레시로 또 다시 받기를 시도한다
        mvc.perform(post("/api/v1/auth/refresh").cookie(first))
                // (도구) status().isUnauthorized() = 응답 코드가 401인지 본다
                // 확인: 401이어야 한다 = 도난 토큰 재사용 차단
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 REFRESH_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("REFRESH_INVALID"));

        // (도구) header("Authorization", "Bearer 토큰") = 로그인 토큰을 붙인다
        // 실행: 새 리프레시 쿠키와 액세스 토큰으로 로그아웃한다
        mvc.perform(post("/api/v1/auth/logout").cookie(second).header("Authorization", "Bearer " + access))
                // (도구) status().isNoContent() = 응답 코드가 204(성공, 내용 없음)인지 본다
                // 확인: 204여야 한다
                .andExpect(status().isNoContent())
                // 확인: 리프레시 쿠키를 지워야 한다(유지 기간 0)
                .andExpect(cookie().maxAge("trace_refresh", 0));
        // 실행: 로그아웃한 리프레시로 다시 받기를 시도한다
        mvc.perform(post("/api/v1/auth/refresh").cookie(second))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized());
    }

    // [상황] 비밀번호를 틀리고, 이메일 인증을 아직 안 한 고객으로 로그인한다.
    // [기대] 틀린 비밀번호는 401, 인증 전 고객은 403.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨), 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("틀린 비밀번호는 401이고 인증 전 고객은 403이다")
    void loginFailures() throws Exception {
        // 준비: 이메일 인증 전(PENDING) 고객 계정을 만든다
        Account pending = customer(AccountStatus.PENDING);
        // 실행: 그 고객 이메일로 엉뚱한 비밀번호를 넣어 로그인한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", NanoId.next()))))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 INVALID_CREDENTIALS(이메일·비밀번호 틀림)여야 한다
                .andExpect(jsonPath("$.code").value("INVALID_CREDENTIALS"));
        // 실행: 맞는 비밀번호로 로그인한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", pending.getEmail(), "password", PASSWORD))))
                // (도구) status().isForbidden() = 응답 코드가 403(권한 없음)인지 본다
                // 확인: 비밀번호는 맞지만 인증 전이라 403이어야 한다
                .andExpect(status().isForbidden())
                // 확인: 오류 코드가 EMAIL_NOT_VERIFIED여야 한다
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));
    }

    // [상황] 관리자가 진단 에이전트용 6자리 페어링 코드를 발급하고, 에이전트가 그 코드를 토큰으로 바꾼다.
    // [기대] DB에는 코드 원문 없이 SHA-256 해시만 저장된다. 한 번만 AGENT 토큰으로 바뀌고, 5분이 지나면 만료된다.
    @Test
    @DisplayName("페어링 코드는 SHA-256 해시만 저장하고 한 번만 AGENT JWT로 바뀌며 5분 뒤 만료된다")
    void pairingCode() throws Exception {
        // 준비: 관리자로 로그인해 토큰을 받는다
        String admin = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
        // 준비: 새 렌탈 ID
        String rentalId = NanoId.next();
        // 준비: 새 시점 ID
        String checkpointId = NanoId.next();

        // 실행: 관리자가 그 렌탈·시점의 페어링 코드를 발급한다
        String code = issuePairing(admin, rentalId, checkpointId);
        // DB에 저장된 그 시점의 코드 칸을 읽는다
        List<String> stored = jdbc.queryForList(
                "select code_hash from auth.pairing_code where checkpoint_id = ?", String.class, checkpointId);
        // (도구) containsExactly(...) = 정확히 그것만 있어야, noneMatch(조건) = 조건에 맞는 게 하나도 없어야 통과
        // 확인: 코드의 SHA-256 해시 하나만 있고, 원문 숫자는 어디에도 없어야 한다
        assertThat(stored).containsExactly(Sha256.hex(code)).noneMatch(h -> h.contains(code));

        // 실행: 에이전트가 그 코드를 토큰으로 바꿔 달라고 요청한다
        MvcResult exchanged = mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", code))))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: AGENT 토큰 유효 시간이 600초(10분)여야 한다
                .andExpect(jsonPath("$.expiresIn").value(600))
                // 확인: 렌탈 ID가 맞아야 한다
                .andExpect(jsonPath("$.rentalId").value(rentalId))
                // 확인: 시점 ID가 맞아야 한다
                .andExpect(jsonPath("$.checkpointId").value(checkpointId))
                // 확인: 기기 일련번호가 발급 때 넣은 값이어야 한다
                .andExpect(jsonPath("$.deviceSerial").value("C02TEST00001"))
                // 응답을 꺼내 둔다
                .andReturn();
        // 받은 토큰의 서명을 확인하고 내용을 꺼낸다
        Jwt agent = jwtDecoder.decode(token(exchanged));
        // (도구) isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 역할이 AGENT여야 한다
        assertThat(agent.getClaimAsString("role")).isEqualTo("AGENT");
        // 확인: 권한 범위가 그 시점 하나여야 한다
        assertThat(agent.getClaimAsString("scope")).isEqualTo(checkpointId);
        // 확인: 렌탈 ID가 들어 있어야 한다
        assertThat(agent.getClaimAsString("rentalId")).isEqualTo(rentalId);
        // 확인: 기기 일련번호가 들어 있어야 한다
        assertThat(agent.getClaimAsString("deviceSerial")).isEqualTo("C02TEST00001");

        // 실행: 같은 코드로 한 번 더 교환한다
        mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", code))))
                // (도구) status().isGone() = 응답 코드가 410(이미 쓰였거나 만료됨)인지 본다
                // 확인: 410이어야 한다 = 한 번만 쓸 수 있다
                .andExpect(status().isGone())
                // 확인: 오류 코드가 PAIRING_CODE_EXPIRED여야 한다
                .andExpect(jsonPath("$.code").value("PAIRING_CODE_EXPIRED"));

        // 준비: 다른 시점으로 새 코드를 발급한다
        String late = issuePairing(admin, rentalId, NanoId.next());
        // 준비: DB에서 그 코드의 만료 시각을 1초 전으로 당긴다(5분 기다리는 대신)
        jdbc.update("update auth.pairing_code set expires_at = now() - interval '1 second' where code_hash = ?",
                Sha256.hex(late));
        // 실행: 만료된 코드로 교환한다
        mvc.perform(post("/api/v1/auth/pairing-codes/exchange")
                        .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("code", late))))
                // 확인: 410이어야 한다
                .andExpect(status().isGone());
    }

    // [상황] 부스(Jetson)가 부스 ID·비밀값으로 토큰을 요청한다. 틀린 비밀값으로도 해 본다.
    // [기대] 맞으면 BOOTH 토큰, 틀리면 401.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("부스 자격은 BOOTH JWT로 바뀌고 틀린 secret은 401이다")
    void boothToken() throws Exception {
        // 실행: 부스 ID·맞는 비밀값으로 부스 토큰을 요청한다
        MvcResult ok = mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", BOOTH_ID, "clientSecret", BOOTH_SECRET))))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 부스 ID가 맞아야 한다
                .andExpect(jsonPath("$.boothId").value(BOOTH_ID))
                // 확인: 부스 토큰 유효 시간이 3600초(1시간)여야 한다
                .andExpect(jsonPath("$.expiresIn").value(3600))
                // 응답을 꺼내 둔다
                .andReturn();
        // 받은 토큰의 서명을 확인하고 내용을 꺼낸다
        Jwt booth = jwtDecoder.decode(token(ok));
        // 확인: 역할이 BOOTH여야 한다
        assertThat(booth.getClaimAsString("role")).isEqualTo("BOOTH");
        // 확인: 권한 범위가 그 부스 ID여야 한다
        assertThat(booth.getClaimAsString("scope")).isEqualTo(BOOTH_ID);

        // 실행: 틀린 비밀값으로 부스 토큰을 요청한다
        mvc.perform(post("/api/v1/auth/booth/token").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("clientId", BOOTH_ID, "clientSecret", NanoId.next()))))
                // 확인: 401이어야 한다
                .andExpect(status().isUnauthorized())
                // 확인: 오류 코드가 CLIENT_CREDENTIALS_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("CLIENT_CREDENTIALS_INVALID"));
    }

    // [상황] 관리자가 렌탈 시점용 QR 링크를 만들고, 고객이 QR을 찍어 교환한다. 다른 고객이 같은 렌탈 QR을 교환해 본다.
    // [기대] 고객은 그 시점에만 쓰는 촬영 JWT를 받고, 렌탈이 고객 계정에 연결된다.
    //        이미 다른 계정에 연결된 렌탈이면 409(남의 렌탈 가로채기 방지).
    //        ※ 응답 코드: 409 = 지금 상태와 맞지 않아 거절(이미 있음·순서 어긋남 등)
    @Test
    @DisplayName("QR 교환은 그 시점만 쓰는 촬영 JWT를 주고 렌탈을 계정에 연결하며, 다른 계정에 연결된 렌탈은 409이다")
    void captureLink() throws Exception {
        // 준비: 관리자로 로그인해 토큰을 받는다
        String admin = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
        // 준비: 새 렌탈 ID
        String rentalId = NanoId.next();
        // 준비: 새 시점 ID
        String checkpointId = NanoId.next();
        // 준비: 렌탈 주인이 될 사용 가능 고객 계정을 만든다
        Account owner = customer(AccountStatus.ACTIVE);
        // 준비: 그 고객으로 로그인해 토큰을 받는다
        String ownerToken = token(login(owner.getEmail(), PASSWORD));

        // 실행: 관리자가 그 렌탈·시점의 QR 링크를 만들고 토큰 부분을 받는다
        String qr = issueLink(admin, rentalId, checkpointId);
        // 확인: DB에는 QR 토큰 원문이 아니라
        assertThat(jdbc.queryForObject("select token_hash from auth.capture_link where checkpoint_id = ?",
                // SHA-256 해시가 저장돼 있어야 한다
                String.class, checkpointId)).isEqualTo(Sha256.hex(qr));

        // 실행: 고객이 QR 토큰을 교환한다
        MvcResult exchanged = exchangeLink(ownerToken, qr)
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 촬영 토큰 유효 시간이 1800초(30분)여야 한다
                .andExpect(jsonPath("$.expiresIn").value(1800))
                // 확인: 렌탈 ID가 맞아야 한다
                .andExpect(jsonPath("$.rentalId").value(rentalId))
                // 응답을 꺼내 둔다
                .andReturn();
        // 받은 촬영 토큰을 꺼낸다
        String capture = token(exchanged);
        // 서명을 확인하고 내용을 꺼낸다
        Jwt captureJwt = jwtDecoder.decode(capture);
        // 확인: 역할이 CUSTOMER여야 한다
        assertThat(captureJwt.getClaimAsString("role")).isEqualTo("CUSTOMER");
        // 확인: 권한 범위가 그 시점 하나여야 한다
        assertThat(captureJwt.getClaimAsString("scope")).isEqualTo(checkpointId);
        // 확인: 토큰 주인이 그 고객이어야 한다
        assertThat(captureJwt.getSubject()).isEqualTo(owner.getPublicId());

        // 고객 JWT로 다른 시점에 접근하면 403: 촬영 JWT는 시점 하나만 들고, 일반 고객 경로도 막힌다
        // 실행: 촬영 토큰으로 내 정보 주소를 부른다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + capture))
                // 확인: 403이어야 한다
                .andExpect(status().isForbidden())
                // 확인: 오류 코드가 FORBIDDEN이어야 한다
                .andExpect(jsonPath("$.code").value("FORBIDDEN"));

        // 실행+확인: 같은 QR을 한 번 더 교환하면 410이어야 하고
        exchangeLink(ownerToken, qr).andExpect(status().isGone())
                // 오류 코드가 CAPTURE_LINK_INVALID여야 한다
                .andExpect(jsonPath("$.code").value("CAPTURE_LINK_INVALID"));

        // 실행: 고객이 다시 로그인해 새 토큰 내용을 꺼낸다
        Jwt relogin = jwtDecoder.decode(token(login(owner.getEmail(), PASSWORD)));
        // 확인: 토큰의 렌탈 목록에 연결된 렌탈 하나가 들어 있어야 한다
        assertThat(relogin.getClaimAsStringList("rentals")).containsExactly(rentalId);
        // 실행: 새로 로그인한 토큰으로 내 정보를 조회한다
        mvc.perform(get("/api/v1/auth/me").header("Authorization", "Bearer " + token(login(owner.getEmail(),
                        PASSWORD))))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 내 렌탈 목록 첫 번째가 그 렌탈이어야 한다
                .andExpect(jsonPath("$.rentalIds[0]").value(rentalId))
                // 확인: 계정 ID가 그 고객이어야 한다
                .andExpect(jsonPath("$.accountId").value(owner.getPublicId()));

        // 준비: 다른 고객 계정을 만든다
        Account other = customer(AccountStatus.ACTIVE);
        // 준비: 그 고객으로 로그인한다
        String otherToken = token(login(other.getEmail(), PASSWORD));
        // 실행: 같은 렌탈의 새 QR을 만들어 다른 고객이 교환한다
        exchangeLink(otherToken, issueLink(admin, rentalId, NanoId.next()))
                // (도구) status().isConflict() = 응답 코드가 409(지금 상태와 맞지 않음)인지 본다
                // 확인: 이미 다른 계정에 연결된 렌탈이라 409여야 한다
                .andExpect(status().isConflict())
                // 확인: 오류 코드가 RENTAL_LINKED_TO_OTHER여야 한다 = 남의 렌탈 가로채기 방지
                .andExpect(jsonPath("$.code").value("RENTAL_LINKED_TO_OTHER"));
    }

    // [상황] 발급한 토큰을 공개키 주소(JWKS)의 공개키로 검증한다.
    // [기대] 검증된다. 다른 서버들(gateway 등)은 이 공개키로 토큰을 확인한다.
    @Test
    @DisplayName("발급한 JWT는 JWKS 공개키로 검증된다")
    void jwks() throws Exception {
        // 준비: 관리자로 로그인해 액세스 토큰을 받는다
        String access = token(login(ADMIN_EMAIL, ADMIN_PASSWORD));
        // 실행: 공개키 주소(JWKS)를 부르고 응답 본문을 꺼낸다
        String body = mvc.perform(get("/.well-known/jwks.json"))
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // 확인: 열쇠 종류가 RSA여야 한다
                .andExpect(jsonPath("$.keys[0].kty").value("RSA"))
                // 확인: 서명 방식이 RS256이어야 한다
                .andExpect(jsonPath("$.keys[0].alg").value("RS256"))
                // 확인: 서명용 열쇠여야 한다
                .andExpect(jsonPath("$.keys[0].use").value("sig"))
                // 응답 본문을 글자로 꺼낸다
                .andReturn().getResponse().getContentAsString();
        // JWKS 글자에서 첫 공개키를 읽는다
        RSAKey key = (RSAKey) JWKSet.parse(body).getKeys().get(0);
        // 액세스 토큰을 서명된 JWT로 읽는다
        SignedJWT jwt = SignedJWT.parse(access);
        // 확인: 토큰 머리의 열쇠 이름(kid)이 공개키 이름과 같아야 한다
        assertThat(jwt.getHeader().getKeyID()).isEqualTo(key.getKeyID());
        // (도구) isTrue() = 값이 true여야 통과
        // 확인: 공개키로 서명 검증이 통과해야 한다 = gateway 등 다른 서버도 이렇게 확인한다
        assertThat(jwt.verify(new RSASSAVerifier(key))).isTrue();
        // (도구) isFalse() = 값이 false여야 통과
        // 확인: 공개된 열쇠에 비밀 부분이 없어야 한다
        assertThat(key.isPrivate()).isFalse();
    }

    // 테스트 도구: 그 상태의 시험용 고객 계정을 DB에 만든다(비밀번호는 PASSWORD의 해시)
    private Account customer(AccountStatus status) {
        // 겹치지 않는 새 이메일을 만든다
        String email = "c-" + NanoId.next().toLowerCase() + "@trace.test";
        // 이름 "고객"인 고객 계정을 저장해 돌려준다
        return accounts.save(Account.customer(NanoId.next(), email, passwordEncoder.encode(PASSWORD), "고객",
                status, Clock.systemUTC().instant()));
    }

    // 테스트 도구: 이메일·비밀번호로 로그인하고 200인지 확인한 뒤 응답을 돌려준다
    private MvcResult login(String email, String password) throws Exception {
        // 로그인 요청을 보내
        return mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("email", email, "password", password))))
                // 200인지 확인하고
                .andExpect(status().isOk())
                // 응답을 돌려준다
                .andReturn();
    }

    // 테스트 도구: 관리자 토큰으로 페어링 코드(기기 일련번호 C02TEST00001)를 발급하고 코드를 돌려준다
    private String issuePairing(String admin, String rentalId, String checkpointId) throws Exception {
        // 페어링 코드 발급 요청을 보내
        MvcResult issued = mvc.perform(post("/api/v1/auth/pairing-codes").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("rentalId", rentalId, "checkpointId", checkpointId,
                                "deviceSerial", "C02TEST00001"))))
                // (도구) status().isCreated() = 응답 코드가 201(새로 만들어짐)인지 본다
                // 201인지 확인하고
                .andExpect(status().isCreated())
                // (도구) isString() = 그 칸이 글자여야 통과
                // 코드 칸이 글자인지 확인한 뒤
                .andExpect(jsonPath("$.code").isString())
                // 응답을 꺼낸다
                .andReturn();
        // 응답에서 코드를 꺼내 돌려준다
        return read(issued).get("code").asText();
    }

    // 테스트 도구: 관리자 토큰으로 QR 링크를 만들고, 주소에서 토큰 부분만 돌려준다
    private String issueLink(String admin, String rentalId, String checkpointId) throws Exception {
        // QR 링크 발급 요청을 보내
        MvcResult issued = mvc.perform(post("/api/v1/auth/capture-links").header("Authorization", "Bearer " + admin)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(body(Map.of("rentalId", rentalId, "checkpointId", checkpointId))))
                // 201인지 확인하고
                .andExpect(status().isCreated())
                // (도구) header().doesNotExist(이름) = 그 머리말이 없어야 통과
                // 쿠키를 심지 않았는지 확인한 뒤
                .andExpect(header().doesNotExist("Set-Cookie"))
                // 응답을 꺼낸다
                .andReturn();
        // 응답에서 QR 주소를 꺼낸다
        String url = read(issued).get("url").asText();
        // (도구) startsWith(글자) = 그 글자로 시작해야 통과
        // 주소가 웹 촬영 화면(capture?t=)이어야 한다
        assertThat(url).startsWith("https://web.trace.test/capture?t=");
        // "t=" 뒤의 토큰 부분만 잘라 돌려준다
        return url.substring(url.indexOf("t=") + 2);
    }

    // 테스트 도구: 고객 토큰으로 QR 토큰 교환을 요청한다(결과 검사는 부른 쪽에서)
    private org.springframework.test.web.servlet.ResultActions exchangeLink(String customer, String qr)
            throws Exception {
        // QR 교환 요청을 보낸다
        return mvc.perform(post("/api/v1/auth/capture-links/exchange").header("Authorization", "Bearer " + customer)
                .contentType(MediaType.APPLICATION_JSON).content(body(Map.of("token", qr))));
    }

    // 테스트 도구: 응답에서 액세스 토큰을 꺼낸다
    private String token(MvcResult result) throws Exception {
        // accessToken 칸을 글자로 돌려준다
        return read(result).get("accessToken").asText();
    }

    // 테스트 도구: 응답 본문을 JSON으로 읽는다
    private JsonNode read(MvcResult result) throws Exception {
        // 본문 글자를 JSON으로 바꿔 돌려준다
        return json.readTree(result.getResponse().getContentAsString());
    }

    // 테스트 도구: 이름-값 지도를 JSON 요청 본문으로 만든다
    private String body(Map<String, String> values) throws Exception {
        // 지도를 JSON 글자로 바꿔 돌려준다
        return json.writeValueAsString(values);
    }
}
