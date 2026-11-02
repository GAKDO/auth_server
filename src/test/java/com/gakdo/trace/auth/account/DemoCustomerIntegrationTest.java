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

/** 시연용 고객 계정이 실제 DB(Flyway auth 스키마)에 만들어지고 로그인되는지 확인한다. */
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
        assertThat(row.get("role")).isEqualTo("CUSTOMER");
        assertThat(row.get("status")).isEqualTo("ACTIVE");
        assertThat(row.get("email_verified_at")).isNotNull();
    }

    @Test
    @DisplayName("서버를 두 번 시작해도 시연용 고객 계정은 하나다")
    void startingTwiceKeepsOneAccount() {
        loader.run(new DefaultApplicationArguments());

        Integer count = jdbc.queryForObject("select count(*) from auth.account where email = ?", Integer.class, EMAIL);
        assertThat(count).isEqualTo(1);
    }
}
