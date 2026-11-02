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
@ExtendWith(OutputCaptureExtension.class)
class InitialDataLoaderTest {

    private static final Instant NOW = Instant.parse("2026-11-02T00:00:00Z");
    // 비밀번호 모양의 문자열을 커밋에 두지 않으려고(gitleaks) 실행할 때마다 만든다
    private static final String PASSWORD = NanoId.next();

    private final AccountRepository accounts = mock(AccountRepository.class);
    private final ClientCredentialRepository clients = mock(ClientCredentialRepository.class);
    private final PasswordEncoder encoder = mock(PasswordEncoder.class);
    private final Clock clock = Clock.fixed(NOW, ZoneOffset.UTC);

    @Test
    @DisplayName("값이 있으면 시작할 때 이메일 인증을 마친 CUSTOMER 계정을 만들고 비밀번호는 해시로만 저장한다")
    void createsVerifiedCustomer(CapturedOutput output) {
        when(accounts.existsByEmail("demo@trace.test")).thenReturn(false);
        when(encoder.encode(PASSWORD)).thenReturn("hashed");

        loader(new AuthProperties.DemoCustomer(" Demo@Trace.test ", PASSWORD)).seedDemoCustomer();

        ArgumentCaptor<Account> saved = ArgumentCaptor.forClass(Account.class);
        verify(accounts).save(saved.capture());
        Account account = saved.getValue();
        assertThat(account.getEmail()).isEqualTo("demo@trace.test");
        assertThat(account.getRole()).isEqualTo(AccountRole.CUSTOMER);
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(account.getPasswordHash()).isEqualTo("hashed");
        assertThat(account.getPublicId()).hasSize(21);
        assertThat(output).doesNotContain(PASSWORD);
    }

    @Test
    @DisplayName("값이 없으면 시연용 고객 계정을 만들지 않는다")
    void skipsWhenNotConfigured() {
        loader(null).seedDemoCustomer();
        loader(new AuthProperties.DemoCustomer("demo@trace.test", "")).seedDemoCustomer();
        loader(new AuthProperties.DemoCustomer(" ", PASSWORD)).seedDemoCustomer();

        verify(accounts, never()).save(any());
    }

    @Test
    @DisplayName("같은 이메일 계정이 이미 있으면 건드리지 않는다(비밀번호를 덮어쓰지 않음)")
    void keepsExistingAccount() {
        when(accounts.existsByEmail("demo@trace.test")).thenReturn(true);

        loader(new AuthProperties.DemoCustomer("demo@trace.test", PASSWORD)).seedDemoCustomer();

        verify(accounts, never()).save(any());
        verify(encoder, never()).encode(any());
    }

    private InitialDataLoader loader(AuthProperties.DemoCustomer demo) {
        Duration d = Duration.ofMinutes(10);
        AuthProperties properties = new AuthProperties("trace", "", false, "trace:", "http://localhost:8315",
                d, d, d, d, d, d, d, true, null, null, demo);
        return new InitialDataLoader(accounts, clients, encoder, properties, clock);
    }
}
