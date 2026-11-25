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
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class DemoCustomerIntegrationTest extends IntegrationTestBase {

    // 같은 DB로 다시 돌려도 겹치지 않게 실행마다 새 이메일을 쓴다(초기 데이터는 없을 때만 생성)
    private static final String EMAIL = "demo-" + NanoId.next().toLowerCase() + "@trace.test";
    private static final String PASSWORD = NanoId.next();

    @DynamicPropertySource
    static void demoCustomer(DynamicPropertyRegistry registry) {
        registry.add("trace.auth.demo-customer.email", () -> EMAIL);
        registry.add("trace.auth.demo-customer.password", () -> PASSWORD);
    }

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;
    @Autowired
    JdbcTemplate jdbc;
    @Autowired
    InitialDataLoader loader;

    // [상황] 시연용 고객 이메일·비밀번호를 설정하고 서버를 켠 뒤 그 계정으로 로그인한다.
    // [기대] CUSTOMER 토큰을 받고, DB에는 사용 가능·이메일 인증 완료 상태로 저장돼 있다.
    @Test
    @DisplayName("값이 있으면 시작할 때 만들어진 시연용 고객 계정으로 로그인하면 CUSTOMER 액세스 JWT를 받는다")
    void demoCustomerCanLogIn() throws Exception {
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", EMAIL, "password", PASSWORD))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.role").value("CUSTOMER"))
                .andExpect(jsonPath("$.accessToken").isNotEmpty());

        Map<String, Object> row = jdbc.queryForMap(
                "select role, status, email_verified_at from auth.account where email = ?", EMAIL);
        assertThat(row).containsEntry("role", "CUSTOMER").containsEntry("status", "ACTIVE");
        assertThat(row.get("email_verified_at")).isNotNull();
    }

    // [상황] 서버를 다시 켠 것처럼 초기 데이터 작업을 한 번 더 돌린다.
    // [기대] 시연용 계정은 여전히 하나뿐이다(중복 생성 없음).
    @Test
    @DisplayName("서버를 두 번 시작해도 시연용 고객 계정은 하나다")
    void startingTwiceKeepsOneAccount() {
        loader.run(new DefaultApplicationArguments());

        Integer count = jdbc.queryForObject("select count(*) from auth.account where email = ?", Integer.class, EMAIL);
        assertThat(count).isEqualTo(1);
    }
}
