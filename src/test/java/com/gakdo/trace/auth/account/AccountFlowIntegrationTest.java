package com.gakdo.trace.auth.account;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIf;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.account.application.CodeMailer;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.support.IntegrationTestBase;

/** AU2 수용 기준을 실제 PostgreSQL(auth.email_token)·Redis로: 가입 → 인증 전 로그인 403 → 인증 → 로그인 → 탈퇴. */
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class AccountFlowIntegrationTest extends IntegrationTestBase {

    private static final String PASSWORD = NanoId.next();

    @Autowired
    MockMvc mvc;
    @Autowired
    ObjectMapper json;
    @Autowired
    JdbcTemplate jdbc;
    @MockitoBean
    CodeMailer mailer;

    @Test
    @DisplayName("가입하면 코드 해시만 저장되고, 인증 전 로그인은 403, 인증 뒤 로그인되며, 탈퇴하면 개인정보가 DB에 남지 않는다")
    void signupVerifyLoginWithdraw() throws Exception {
        String email = "renter-" + NanoId.next().toLowerCase() + "@trace.test";
        AtomicReference<String> code = new AtomicReference<>();
        doAnswer(i -> {
            code.set(i.getArgument(2));
            return null;
        }).when(mailer).send(eq(email), eq(EmailTokenPurpose.VERIFY), any());

        String accountId = json.readTree(mvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", PASSWORD,
                                "name", "홍길동", "privacyAgreed", true))))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn().getResponse().getContentAsString()).get("accountId").asText();

        assertThat(code.get()).matches("\\d{6}");
        assertThat(jdbc.queryForObject("SELECT t.code_hash FROM auth.email_token t JOIN auth.account a "
                + "ON a.id = t.account_id WHERE a.public_id = ?", String.class, accountId))
                .isEqualTo(Sha256.hex(code.get()));

        String login = json.writeValueAsString(Map.of("email", email, "password", PASSWORD));
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(login))
                .andExpect(status().isForbidden())
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));

        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "code", code.get()))))
                .andExpect(status().isNoContent());

        String token = json.readTree(mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(login))
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("accessToken").asText();

        mvc.perform(delete("/api/v1/auth/me").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("password", PASSWORD))))
                .andExpect(status().isNoContent());

        Map<String, Object> row = jdbc.queryForMap(
                "SELECT email, name, password_hash, status FROM auth.account WHERE public_id = ?", accountId);
        assertThat(row.get("email")).isNull();
        assertThat(row.get("name")).isNull();
        assertThat(row.get("password_hash")).isNull();
        assertThat(row).containsEntry("status", "WITHDRAWN");
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(login))
                .andExpect(status().isUnauthorized());
    }
}
