// 이 파일이 확인하는 것: 시연용 고객 계정 초기 데이터(DEMO_CUSTOMER_EMAIL·DEMO_CUSTOMER_PASSWORD) 규칙을 DB 없이 확인.

package com.gakdo.trace.auth.account.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.booth.domain.ClientCredentialRepository;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.config.AuthProperties;

/** 시연용 고객 계정 초기 데이터(DEMO_CUSTOMER_EMAIL·DEMO_CUSTOMER_PASSWORD)를 DB 없이 확인한다. */
// (도구) @ExtendWith(OutputCaptureExtension) = 테스트 중 화면·로그에 찍힌 글자를 붙잡아 검사할 수 있게 한다
@ExtendWith(OutputCaptureExtension.class)
class InitialDataLoaderTest {

    // 시험 속 "지금" 시각을 고정한다
    private static final Instant NOW = Instant.parse("2026-11-02T00:00:00Z");
    // 비밀번호 모양의 문자열을 커밋에 두지 않으려고(gitleaks) 실행할 때마다 만든다
    private static final String PASSWORD = NanoId.next();

    // (도구) mock(종류) = 진짜 대신 가짜 객체를 만든다. 여기서는 DB 없이 돌리려고 저장소들을 가짜로 둔다
    // 계정 저장소(가짜)
    private final AccountRepository accounts = mock(AccountRepository.class);
    // 부스 등 기계 계정 저장소(가짜)
    private final ClientCredentialRepository clients = mock(ClientCredentialRepository.class);
    // 비밀번호 해시 도구(가짜). 해시 결과를 정해 둘 수 있게
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    // 항상 NOW를 가리키는 고정 시계
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    // [상황] 시연용 이메일(앞뒤 공백·대문자 섞임)과 비밀번호를 설정하고 서버를 켠다.
    // [기대] 이메일을 소문자로 정리해 인증 끝난 CUSTOMER 계정을 만든다. 비밀번호는 해시로만 저장하고 로그에 남기지 않는다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름. CapturedOutput = 붙잡은 로그 글자
    @Test
    @DisplayName("값이 있으면 시작할 때 이메일 인증을 마친 CUSTOMER 계정을 만들고 비밀번호는 해시로만 저장한다")
    void createsVerifiedCustomer(CapturedOutput output) {
        // (도구) when(가짜.메서드(값)).thenReturn(결과) = "가짜에게 이 질문이 오면 이 결과를 돌려줘"라고 미리 정해 두는 것
        // 준비: 그 이메일 계정은 아직 없다고 답하게 한다
        when(accounts.existsByEmail("demo@trace.test")).thenReturn(false);
        // 준비: 비밀번호를 해시하면 "hashed"가 나오게 한다
        when(encoder.encode(PASSWORD)).thenReturn("hashed");

        // 실행: 앞뒤 공백·대문자가 섞인 이메일로 시연용 고객 계정 만들기를 돌린다
        loader(new AuthProperties.DemoCustomer(" Demo@Trace.test ", PASSWORD)).seedDemoCustomer();

        // (도구) ArgumentCaptor = 가짜에게 넘어간 값을 붙잡아 두는 그물. 나중에 getValue()로 꺼낸다
        // 저장된 계정을 붙잡을 그물을 만든다
        ArgumentCaptor<Account> saved = ArgumentCaptor.forClass(Account.class);
        // (도구) verify(가짜).메서드(...) = 그 메서드가 (한 번) 불렸는지 확인한다
        // 확인: 계정 저장이 불렸어야 하고, 그 계정을 그물에 담는다
        verify(accounts).save(saved.capture());
        // 붙잡은 계정을 꺼낸다
        Account account = saved.getValue();
        // (도구) assertThat(값).isEqualTo(기대값) = "값이 기대값과 같아야 한다"를 확인하는 AssertJ 도구
        // 확인: 이메일이 공백 없는 소문자로 정리돼야 한다
        assertThat(account.getEmail()).isEqualTo("demo@trace.test");
        // 확인: 역할이 CUSTOMER여야 한다
        assertThat(account.getRole()).isEqualTo(AccountRole.CUSTOMER);
        // 확인: 상태가 ACTIVE(사용 가능)여야 한다
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        // 확인: 비밀번호는 원문이 아니라 해시 값으로 저장돼야 한다
        assertThat(account.getPasswordHash()).isEqualTo("hashed");
        // (도구) hasSize(n) = 길이가 n이어야 통과
        // 확인: 공개 ID가 21자여야 한다
        assertThat(account.getPublicId()).hasSize(21);
        // (도구) doesNotContain(글자) = 그 글자가 없어야 통과
        // 확인: 로그에 비밀번호 원문이 찍히지 않았어야 한다
        assertThat(output).doesNotContain(PASSWORD);
    }

    // [상황] 설정이 없거나, 비밀번호가 비었거나, 이메일이 공백이다.
    // [기대] 계정을 만들지 않는다.
    @Test
    @DisplayName("값이 없으면 시연용 고객 계정을 만들지 않는다")
    void skipsWhenNotConfigured() {
        // 실행: 시연용 고객 설정이 아예 없는 경우
        loader(null).seedDemoCustomer();
        // 실행: 비밀번호가 빈 경우
        loader(new AuthProperties.DemoCustomer("demo@trace.test", "")).seedDemoCustomer();
        // 실행: 이메일이 공백뿐인 경우
        loader(new AuthProperties.DemoCustomer(" ", PASSWORD)).seedDemoCustomer();

        // (도구) never() = 한 번도 불리지 않았어야 통과. any() = 아무 값이나
        // 확인: 세 경우 모두 계정을 저장하지 않았어야 한다
        verify(accounts, never()).save(any());
    }

    // [상황] 같은 이메일 계정이 이미 있다.
    // [기대] 건드리지 않는다(재시작 때 고객이 바꾼 비밀번호를 덮어쓰지 않음).
    @Test
    @DisplayName("같은 이메일 계정이 이미 있으면 건드리지 않는다(비밀번호를 덮어쓰지 않음)")
    void keepsExistingAccount() {
        // 준비: 같은 이메일 계정이 이미 있다고 답하게 한다
        when(accounts.existsByEmail("demo@trace.test")).thenReturn(true);

        // 실행: 시연용 고객 계정 만들기를 돌린다
        loader(new AuthProperties.DemoCustomer("demo@trace.test", PASSWORD)).seedDemoCustomer();

        // 확인: 계정을 다시 저장하지 않았어야 한다
        verify(accounts, never()).save(any());
        // 확인: 비밀번호를 해시하지도 않았어야 한다 = 고객이 바꾼 비밀번호를 덮어쓰지 않는다
        verify(encoder, never()).encode(any());
    }

    // 테스트 도구: 시연용 고객 설정만 바꿔 초기 데이터 작업을 만든다
    private InitialDataLoader loader(AuthProperties.DemoCustomer demo) {
        // 시험에 상관없는 유효 시간들은 모두 10분으로 둔다
        Duration d = Duration.ofMinutes(10);
        // 받은 시연용 고객 설정을 넣은 인증 설정을 만든다
        AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://localhost:8315",
                d, d, d, d, d, d, d, true, null, null, demo);
        // 가짜 저장소·해시 도구·고정 시계로 초기 데이터 작업을 만들어 돌려준다
        return new InitialDataLoader(accounts, clients, encoder, properties, clock);
    }
}
