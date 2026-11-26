// 이 파일이 확인하는 것: 시연(대회 발표)용 고객 계정이 진짜 DB에 만들어지고 로그인되는지.
// 이메일·비밀번호는 환경 변수로 받으며, 테스트에서는 실행할 때마다 새로 만든다.

package com.gakdo.trace.auth.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.DefaultApplicationArguments;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.account.application.InitialDataLoader;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.support.IntegrationTestBase;

/**
 * 시연(대회 발표)용 고객 계정이 실제 DB(Flyway auth 스키마)에 만들어지고 로그인되는지 확인한다.
 *
 * <p>확인하는 흐름: 환경 변수로 이메일·비밀번호를 주고 서버 시작 → 그 계정으로 로그인하면 CUSTOMER 토큰 →
 * 서버를 두 번 시작해도 계정은 하나. 이메일·비밀번호는 실행할 때마다 새로 만든 값이다.
 *
 * <p>실행 조건: 진짜 PostgreSQL·Redis가 필요하다(바탕 클래스 IntegrationTestBase).
 * GitHub Actions는 Docker(Testcontainers)로 띄우고, Docker가 없으면 {@code TRACE_IT_LOCAL=1}일 때 로컬 테스트 전용 DB
 * trace_it·Redis DB 15에 붙는다. 둘 다 없으면 이 클래스 전체를 건너뛴다(실패가 아님).
 */
// (도구) @AutoConfigureMockMvc = 서버 전체를 띄운 상태에서 MockMvc(가짜 HTTP 요청 도구)도 쓸 수 있게 한다. @EnabledIf = 조건(진짜 DB를 쓸 수 있는지)이 맞을 때만 돌린다
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class DemoCustomerIntegrationTest extends IntegrationTestBase {

    // 같은 DB로 다시 돌려도 겹치지 않게 실행마다 새 이메일을 쓴다(초기 데이터는 없을 때만 생성)
    private static final String EMAIL = "demo-" + NanoId.next().toLowerCase() + "@trace.test";
    // 비밀번호도 실행마다 무작위로 만든다(비밀값을 코드에 두지 않으려고)
    private static final String PASSWORD = NanoId.next();

    // (도구) @DynamicPropertySource = 서버가 뜨기 전에 설정 값을 코드로 넣는다
    @DynamicPropertySource
    static void demoCustomer(DynamicPropertyRegistry registry) {
        // 시연용 고객 이메일 설정에 위 이메일을 넣는다(환경 변수 DEMO_CUSTOMER_EMAIL 대신)
        registry.add("trace.auth.demo-customer.email", () -> EMAIL);
        // 시연용 고객 비밀번호 설정에 위 비밀번호를 넣는다
        registry.add("trace.auth.demo-customer.password", () -> PASSWORD);
    }

    // (도구) @Autowired = 스프링이 만들어 둔 부품을 넣어 준다. MockMvc = 진짜 네트워크 없이 HTTP 요청을 흉내 내는 도구
    @Autowired
    MockMvc mvc;
    // 요청 본문을 JSON으로 만드는 도구
    @Autowired
    ObjectMapper json;
    // (도구) JdbcTemplate = SQL을 직접 실행해 DB 내용을 확인하는 도구
    @Autowired
    JdbcTemplate jdbc;
    // 서버 시작 때 초기 데이터를 넣는 작업(두 번 돌려 보려고 받는다)
    @Autowired
    InitialDataLoader loader;

    // [상황] 시연용 고객 이메일·비밀번호를 설정하고 서버를 켠 뒤 그 계정으로 로그인한다.
    // [기대] CUSTOMER 토큰을 받고, DB에는 사용 가능·이메일 인증 완료 상태로 저장돼 있다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("값이 있으면 시작할 때 만들어진 시연용 고객 계정으로 로그인하면 CUSTOMER 액세스 JWT를 받는다")
    void demoCustomerCanLogIn() throws Exception {
        // (도구) perform(post(주소).contentType(JSON).content(본문)) = JSON 본문을 담아 POST 요청을 보낸다. andExpect(...) = 응답 검사
        // 실행: 시연용 이메일·비밀번호로 로그인을 요청한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                // (도구) status().isOk() = 응답 코드가 200(정상)인지 본다
                // 확인: 200이어야 한다
                .andExpect(status().isOk())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸 값을 꺼낸다
                // 확인: 역할이 CUSTOMER(고객)여야 한다
                .andExpect(jsonPath("$.role").value("CUSTOMER"))
                // (도구) isNotEmpty() = 값이 비어 있지 않아야 통과
                // 확인: 액세스 토큰을 받아야 한다
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        // 실행: DB에서 그 이메일 계정의 역할·상태·이메일 인증 시각을 읽는다
        Map<String, Object> row = jdbc.queryForMap(
                "select role, status, email_verified_at from auth.account where email = ?", EMAIL);
        // (도구) assertThat(값).containsEntry(열쇠, 값) = 지도에 그 열쇠·값 짝이 있어야 통과
        // 확인: 역할 CUSTOMER, 상태 ACTIVE(사용 가능)로 저장돼 있어야 한다
        assertThat(row).containsEntry("role", "CUSTOMER").containsEntry("status", "ACTIVE");
        // (도구) isNotNull() = 값이 있어야 통과
        // 확인: 이메일 인증 시각이 채워져 있어야 한다 = 인증 메일 없이 바로 로그인 가능
        assertThat(row.get("email_verified_at")).isNotNull();
    }

    // [상황] 서버를 다시 켠 것처럼 초기 데이터 작업을 한 번 더 돌린다.
    // [기대] 시연용 계정은 여전히 하나뿐이다(중복 생성 없음).
    @Test
    @DisplayName("서버를 두 번 시작해도 시연용 고객 계정은 하나다")
    void startingTwiceKeepsOneAccount() {
        // 실행: 서버를 다시 켠 것처럼 초기 데이터 작업을 한 번 더 돌린다
        loader.run(new DefaultApplicationArguments());

        // 그 이메일 계정 수를 DB에서 센다
        Integer count = jdbc.queryForObject("select count(*) from auth.account where email = ?", Integer.class, EMAIL);
        // 확인: 계정이 하나뿐이어야 한다 = 두 번 만들지 않는다
        assertThat(count).isEqualTo(1);
    }
}
