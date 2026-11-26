// 이 파일이 확인하는 것: 요구사항 AU2(회원 가입·탈퇴) 흐름을 진짜 DB·Redis로 한 번에 확인.

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

/**
 * AU2(회원 가입·탈퇴) 수용 기준을 실제 PostgreSQL(auth.email_token 표)·Redis로 확인한다.
 *
 * <p>확인하는 흐름: 가입(메일 인증 코드는 해시만 저장) → 인증 전 로그인은 403(권한 없음) → 코드로 인증 → 로그인 →
 * 탈퇴하면 개인정보가 지워짐.
 *
 * <p>실행 조건: 진짜 PostgreSQL·Redis가 필요하다(바탕 클래스 IntegrationTestBase).
 * GitHub Actions는 Docker(Testcontainers)로 띄우고, Docker가 없으면 {@code TRACE_IT_LOCAL=1}일 때 로컬 테스트 전용 DB
 * trace_it·Redis DB 15에 붙는다. 둘 다 없으면 이 클래스 전체를 건너뛴다(실패가 아님).
 */
// ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
// (도구) @AutoConfigureMockMvc = 서버 전체를 띄운 상태에서 MockMvc(가짜 HTTP 요청 도구)도 쓸 수 있게 한다. @EnabledIf = 진짜 DB를 쓸 수 있을 때만 돌린다
@AutoConfigureMockMvc
@EnabledIf("com.gakdo.trace.auth.support.IntegrationTestBase#infrastructureAvailable")
class AccountFlowIntegrationTest extends IntegrationTestBase {

    // 비밀번호는 실행마다 무작위로 만든다(비밀값을 코드에 두지 않으려고)
    private static final String PASSWORD = NanoId.next();

    // (도구) @Autowired = 스프링이 만들어 둔 부품을 넣어 준다. MockMvc = 진짜 네트워크 없이 HTTP 요청을 흉내 내는 도구
    @Autowired
    MockMvc mvc;
    // 요청 본문 JSON을 만들고 응답 JSON을 읽는 도구
    @Autowired
    ObjectMapper json;
    // (도구) JdbcTemplate = SQL을 직접 실행해 DB 내용을 확인하는 도구
    @Autowired
    JdbcTemplate jdbc;
    // (도구) @MockitoBean = 진짜 대신 가짜(목)를 스프링에 끼워 넣는다. 인증 코드 메일을 실제로 보내지 않고 코드만 가로채려고
    @MockitoBean
    CodeMailer mailer;

    // [상황] 가입 → 인증 전 로그인 → 메일 코드로 인증 → 로그인 → 탈퇴 → 다시 로그인 순서로 진행한다.
    // [기대] DB에는 인증 코드 해시만 저장된다. 인증 전 로그인은 403 EMAIL_NOT_VERIFIED, 인증 뒤엔 로그인된다.
    //        탈퇴하면 이메일·이름·비밀번호가 DB에서 지워지고(WITHDRAWN), 같은 정보로 다시 로그인하면 401.
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일), 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("가입하면 코드 해시만 저장되고, 인증 전 로그인은 403, 인증 뒤 로그인되며, 탈퇴하면 개인정보가 DB에 남지 않는다")
    void signupVerifyLoginWithdraw() throws Exception {
        // 준비: 다른 실행과 겹치지 않게 새 이메일을 만든다
        String email = "renter-" + NanoId.next().toLowerCase() + "@trace.test";
        // 준비: 메일로 나간 인증 코드를 담아 둘 상자
        AtomicReference<String> code = new AtomicReference<>();
        // (도구) doAnswer(코드).when(가짜).메서드(...) = "가짜의 이 메서드가 불리면 이 코드를 돌려라". 반환값 없는(void) 메서드에 쓴다
        // 준비: 인증 코드 메일 보내기가 불리면 세 번째 값(코드)을 상자에 담게 한다
        doAnswer(i -> {
            // 보내려던 6자리 코드를 상자에 담는다
            code.set(i.getArgument(2));
            // void 메서드라 돌려줄 값은 없다
            return null;
        }).when(mailer).send(eq(email), eq(EmailTokenPurpose.VERIFY), any());

        // (도구) perform(post(주소)...) = POST 요청을 보낸다. andExpect(...) = 응답 검사. andReturn()... = 응답 본문을 꺼낸다
        // 실행: 이메일·비밀번호·이름·개인정보 동의로 가입을 요청하고, 응답에서 계정 ID를 꺼낸다
        String accountId = json.readTree(mvc.perform(post("/api/v1/auth/signup")
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "password", PASSWORD,
                                "name", "홍길동", "privacyAgreed", true))))
                // (도구) status().isCreated() = 응답 코드가 201(새로 만들어짐)인지 본다
                // 확인: 201이어야 한다
                .andExpect(status().isCreated())
                // (도구) jsonPath("$.칸") = 응답 JSON에서 그 칸 값을 꺼낸다
                // 확인: 상태가 PENDING(메일 인증 대기)이어야 한다
                .andExpect(jsonPath("$.status").value("PENDING"))
                .andReturn().getResponse().getContentAsString()).get("accountId").asText();

        // (도구) assertThat(값).matches(정규식) = 글자 모양이 규칙에 맞는지 보는 AssertJ 검사
        // 확인: 메일로 나간 코드가 숫자 6자리여야 한다
        assertThat(code.get()).matches("\\d{6}");
        // 실행: DB에서 이 계정의 인증 코드 칸을 읽어
        assertThat(jdbc.queryForObject("SELECT t.code_hash FROM auth.email_token t JOIN auth.account a "
                + "ON a.id = t.account_id WHERE a.public_id = ?", String.class, accountId))
                // 확인: 코드 원문이 아니라 SHA-256 해시로 저장돼 있어야 한다 = DB가 새도 코드를 알 수 없다
                .isEqualTo(Sha256.hex(code.get()));

        // 준비: 로그인 요청 본문(이메일·비밀번호)을 만든다
        String login = json.writeValueAsString(Map.of("email", email, "password", PASSWORD));
        // 실행: 메일 인증 전에 로그인을 요청한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(login))
                // (도구) status().isForbidden() = 응답 코드가 403(권한 없음)인지 본다
                // 확인: 403이어야 한다
                .andExpect(status().isForbidden())
                // 확인: 오류 코드가 EMAIL_NOT_VERIFIED(이메일 미인증)여야 한다
                .andExpect(jsonPath("$.code").value("EMAIL_NOT_VERIFIED"));

        // 실행: 가로챈 코드로 이메일 인증을 요청한다
        mvc.perform(post("/api/v1/auth/email/verify").contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("email", email, "code", code.get()))))
                // (도구) status().isNoContent() = 응답 코드가 204(성공, 돌려줄 내용 없음)인지 본다
                // 확인: 204여야 한다
                .andExpect(status().isNoContent());

        // 실행: 다시 로그인을 요청하고 응답에서 액세스 토큰을 꺼낸다
        String token = json.readTree(mvc.perform(post("/api/v1/auth/login")
                        .contentType(MediaType.APPLICATION_JSON).content(login))
                // (도구) status().isOk() = 응답 코드가 200(정상)인지 본다
                // 확인: 인증 뒤라 200이어야 한다
                .andExpect(status().isOk())
                .andReturn().getResponse().getContentAsString()).get("accessToken").asText();

        // (도구) delete(주소) = DELETE 요청. header("Authorization", "Bearer 토큰") = 로그인 토큰을 붙인다
        // 실행: 받은 토큰과 비밀번호로 탈퇴를 요청한다
        mvc.perform(delete("/api/v1/auth/me").header("Authorization", "Bearer " + token)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content(json.writeValueAsString(Map.of("password", PASSWORD))))
                // 확인: 204여야 한다
                .andExpect(status().isNoContent());

        // 실행: DB에서 그 계정의 이메일·이름·비밀번호 해시·상태를 읽는다
        Map<String, Object> row = jdbc.queryForMap(
                "SELECT email, name, password_hash, status FROM auth.account WHERE public_id = ?", accountId);
        // (도구) isNull() = 값이 없어야(null) 통과
        // 확인: 이메일이 지워졌어야 한다
        assertThat(row.get("email")).isNull();
        // 확인: 이름이 지워졌어야 한다
        assertThat(row.get("name")).isNull();
        // 확인: 비밀번호 해시도 지워졌어야 한다
        assertThat(row.get("password_hash")).isNull();
        // (도구) containsEntry(열쇠, 값) = 지도에 그 열쇠·값 짝이 있어야 통과
        // 확인: 상태가 WITHDRAWN(탈퇴)이어야 한다
        assertThat(row).containsEntry("status", "WITHDRAWN");
        // 실행: 같은 이메일·비밀번호로 다시 로그인을 요청한다
        mvc.perform(post("/api/v1/auth/login").contentType(MediaType.APPLICATION_JSON).content(login))
                // (도구) status().isUnauthorized() = 응답 코드가 401(로그인 실패)인지 본다
                // 확인: 계정 정보가 없어져 401이어야 한다
                .andExpect(status().isUnauthorized());
    }
}
