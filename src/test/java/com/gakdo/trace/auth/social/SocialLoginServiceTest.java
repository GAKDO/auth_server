// 이 파일이 확인하는 것: 소셜 로그인 뒤 TRACE 계정을 찾기·연결·새로 만드는 규칙(DB 대신 메모리 목록).

package com.gakdo.trace.auth.social;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.BDDMockito.given;
import static org.mockito.BDDMockito.willAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;

import com.gakdo.trace.auth.account.application.LoginResult;
import com.gakdo.trace.auth.account.application.LoginService;
import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.social.application.SocialLoginError;
import com.gakdo.trace.auth.social.application.SocialLoginException;
import com.gakdo.trace.auth.social.application.SocialLoginService;
import com.gakdo.trace.auth.social.application.SocialProfile;
import com.gakdo.trace.auth.social.domain.SocialIdentity;
import com.gakdo.trace.auth.social.domain.SocialIdentityRepository;
import com.gakdo.trace.auth.social.domain.SocialProvider;

/** 소셜 로그인 계정 찾기·연결·가입 규칙을 DB 없이(메모리 저장소) 확인한다. */
class SocialLoginServiceTest {

    private static final Instant NOW = Instant.parse("2026-11-10T01:00:00Z");

    private final List<Account> accountRows = new ArrayList<>();
    private final List<SocialIdentity> identityRows = new ArrayList<>();
    private final AccountRepository accounts = mock(AccountRepository.class);
    private final SocialIdentityRepository identities = mock(SocialIdentityRepository.class);
    private final LoginService loginService = mock(LoginService.class);
    private final SecureTokens secureTokens = mock(SecureTokens.class);
    private SocialLoginService service;

    @BeforeEach
    @SuppressWarnings("deprecation")
    void setUp() {
        given(secureTokens.opaqueToken()).willReturn("random-unusable");
        given(accounts.findByEmail(any())).willAnswer(i -> accountRows.stream()
                .filter(a -> i.getArgument(0).equals(a.getEmail())).findFirst());
        given(accounts.findById(anyLong())).willAnswer(i -> accountRows.stream()
                .filter(a -> a.getId().equals(i.getArgument(0))).findFirst());
        given(accounts.saveAndFlush(any())).willAnswer(i -> add(i.getArgument(0)));
        given(identities.findByProviderAndSubject(any(), any())).willAnswer(i -> identityRows.stream()
                .filter(x -> x.getProvider() == i.getArgument(0) && x.getSubject().equals(i.getArgument(1)))
                .findFirst());
        given(identities.findByAccountIdAndProvider(anyLong(), any())).willAnswer(i -> identityRows.stream()
                .filter(x -> x.getAccountId().equals(i.getArgument(0)) && x.getProvider() == i.getArgument(1))
                .findFirst());
        given(identities.save(any())).willAnswer(i -> {
            identityRows.add(i.getArgument(0));
            return i.getArgument(0);
        });
        willAnswer(i -> identityRows.remove(i.<SocialIdentity>getArgument(0)))
                .given(identities).delete(any());
        given(loginService.issueFor(any())).willAnswer(i -> new LoginResult(null, "refresh-for-"
                + i.<Account>getArgument(0).getPublicId(), i.<Account>getArgument(0).getRole()));
        service = new SocialLoginService(identities, accounts, loginService, NoOpPasswordEncoder.getInstance(),
                secureTokens, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    // [상황] 처음 온 깃허브 사용자(이메일 대문자 섞임)가 로그인한다.
    // [기대] 이메일을 소문자로 정리해 바로 사용 가능한 고객 계정을 만들고 로그인시킨다.
    //        비밀번호는 아무도 모르는 값으로 채우고 "비밀번호 정한 적 없음"으로 표시한다. 깃허브 연결도 저장한다.
    @Test
    @DisplayName("처음 온 GitHub 사용자는 인증된 이메일로 ACTIVE 고객 계정이 만들어지고 바로 로그인된다")
    void newUserBecomesActiveCustomer() {
        LoginResult result = service.login(new SocialProfile(SocialProvider.GITHUB, "123", "Dev@Example.com", "개발자"));

        assertThat(accountRows).hasSize(1);
        Account created = accountRows.get(0);
        assertThat(created.getEmail()).isEqualTo("dev@example.com");
        assertThat(created.getRole()).isEqualTo(AccountRole.CUSTOMER);
        assertThat(created.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(created.getName()).isEqualTo("개발자");
        assertThat(created.getPasswordHash()).isEqualTo("random-unusable");
        assertThat(created.isPasswordSet()).isFalse();
        assertThat(identityRows).singleElement().satisfies(i -> {
            assertThat(i.getProvider()).isEqualTo(SocialProvider.GITHUB);
            assertThat(i.getSubject()).isEqualTo("123");
        });
        assertThat(result.refreshToken()).isEqualTo("refresh-for-" + created.getPublicId());
    }

    // [상황] 카카오에서 인증된 이메일을 받지 못했다.
    // [기대] 가입시키지 않고 EMAIL_REQUIRED.
    @Test
    @DisplayName("인증된 이메일을 받지 못하면 가입시키지 않고 EMAIL_REQUIRED")
    void emailIsRequired() {
        SocialProfile noEmail = new SocialProfile(SocialProvider.KAKAO, "9", null, "카카오");
        assertThatThrownBy(() -> service.login(noEmail))
                .isInstanceOf(SocialLoginException.class)
                .extracting(e -> ((SocialLoginException) e).error())
                .isEqualTo(SocialLoginError.EMAIL_REQUIRED);
        assertThat(accountRows).isEmpty();
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 같은 이메일로 가입만 하고 메일 인증을 안 한 계정이 있는데, 구글로 로그인한다.
    // [기대] 새 계정을 만들지 않고 그 계정에 연결하며, 구글이 이메일을 확인해 줬으니 인증 완료(ACTIVE)가 된다.
    //        이름은 원래 것을 유지하고, 남이 미리 정해 둔 비밀번호는 못 쓰게 바꾼다(계정 선점 공격 방지).
    @Test
    @DisplayName("같은 이메일로 가입했지만 메일 인증 전인 계정은 Google 로그인으로 인증이 끝나고 그 계정에 연결된다")
    void linksExistingPendingAccount() {
        Account pending = add(Account.customer(NanoId.next(), "me@trace.test", "hash", "나", AccountStatus.PENDING, NOW));

        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-1", "me@trace.test", "Google 이름"));

        assertThat(accountRows).hasSize(1);
        assertThat(pending.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        assertThat(pending.getName()).isEqualTo("나");
        assertThat(pending.getPasswordHash()).isEqualTo("random-unusable");
        assertThat(pending.isPasswordSet()).isFalse();
        assertThat(identityRows).singleElement().extracting(SocialIdentity::getAccountId).isEqualTo(pending.getId());
    }

    // [상황] 이미 사용 중인 계정에 같은 이메일의 구글 로그인을 연결한다.
    // [기대] 원래 비밀번호는 그대로 둔다.
    @Test
    @DisplayName("이미 ACTIVE인 계정에 연결할 때는 원래 비밀번호를 그대로 둔다")
    void activeAccountKeepsPassword() {
        Account active = add(Account.customer(NanoId.next(), "me@trace.test", "hash", "나", AccountStatus.ACTIVE, NOW));

        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-1", "me@trace.test", "Google 이름"));

        assertThat(active.getPasswordHash()).isEqualTo("hash");
        assertThat(active.isPasswordSet()).isTrue();
    }

    // [상황] 관리자 이메일과 같은 구글 계정으로 로그인한다.
    // [기대] 연결하지 않고 거부한다(관리자 권한을 소셜 로그인으로 얻지 못하게).
    @Test
    @DisplayName("관리자 이메일로 소셜 로그인하면 연결하지 않고 거부한다")
    void adminEmailIsRejected() {
        add(Account.admin(NanoId.next(), "admin@trace.test", "hash", "관리자", NOW));

        SocialProfile adminProfile = new SocialProfile(SocialProvider.GOOGLE, "g-9", "admin@trace.test", "x");
        assertThatThrownBy(() -> service.login(adminProfile))
                .isInstanceOf(SocialLoginException.class);
        assertThat(identityRows).isEmpty();
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 관리자 계정에 이미 깃허브 연결이 붙어 있다.
    // [기대] 그래도 소셜 로그인은 거부한다.
    @Test
    @DisplayName("관리자 계정에 이미 붙은 연결이 있어도 소셜 로그인은 거부한다")
    void linkedAdminIsRejected() {
        Account admin = add(Account.admin(NanoId.next(), "admin@trace.test", "hash", "관리자", NOW));
        identityRows.add(new SocialIdentity(admin.getId(), SocialProvider.GITHUB, "77", "admin@trace.test", NOW));

        SocialProfile linkedProfile = new SocialProfile(SocialProvider.GITHUB, "77", "admin@trace.test", "x");
        assertThatThrownBy(() -> service.login(linkedProfile))
                .isInstanceOf(SocialLoginException.class);
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 깃허브로 가입한 뒤 깃허브 쪽 이메일이 바뀌어서 다시 로그인한다.
    // [기대] 깃허브 사용자 번호로 찾아 같은 TRACE 계정으로 로그인된다.
    @Test
    @DisplayName("한 번 연결된 제공자 계정은 제공자 쪽 이메일이 바뀌어도 같은 TRACE 계정으로 로그인된다")
    void linkedIdentityWinsOverEmail() {
        service.login(new SocialProfile(SocialProvider.GITHUB, "123", "old@example.com", "개발자"));
        String firstId = accountRows.get(0).getPublicId();

        LoginResult again = service.login(new SocialProfile(SocialProvider.GITHUB, "123", "new@example.com", "개발자"));

        assertThat(accountRows).hasSize(1);
        assertThat(again.refreshToken()).isEqualTo("refresh-for-" + firstId);
    }

    // [상황] 네이버로 가입한 고객이 탈퇴한 뒤 같은 네이버 계정으로 다시 온다.
    // [기대] 새 고객 계정으로 가입되고, 네이버 연결은 새 계정으로 옮겨진다.
    @Test
    @DisplayName("탈퇴한 계정에 붙어 있던 제공자 계정으로 다시 오면 새 고객 계정으로 가입된다")
    void withdrawnAccountStartsOver() {
        service.login(new SocialProfile(SocialProvider.NAVER, "n-1", "nv@example.com", "네이버"));
        Account first = accountRows.get(0);
        first.withdraw(NOW);

        service.login(new SocialProfile(SocialProvider.NAVER, "n-1", "nv@example.com", "네이버"));

        assertThat(accountRows).hasSize(2);
        assertThat(identityRows).singleElement().extracting(SocialIdentity::getAccountId)
                .isEqualTo(accountRows.get(1).getId());
    }

    // [상황] 구글에서 이름을 받지 못했다.
    // [기대] 이메일 앞부분(kim)을 이름으로 쓴다.
    @Test
    @DisplayName("이름을 받지 못하면 이메일 앞부분을 이름으로 쓴다")
    void nameFallsBackToEmailLocalPart() {
        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-2", "kim@example.com", null));
        assertThat(accountRows.get(0).getName()).isEqualTo("kim");
    }

    // 도우미: 메모리 목록에 계정을 넣고 번호를 붙인다.
    private Account add(Account account) {
        try {
            var field = Account.class.getDeclaredField("id");
            field.setAccessible(true);
            field.set(account, (long) accountRows.size() + 1);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
        accountRows.add(account);
        return account;
    }
}
