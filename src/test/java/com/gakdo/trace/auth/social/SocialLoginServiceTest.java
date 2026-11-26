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

    // 시험 속 "지금" 시각을 고정한다
    private static final Instant NOW = Instant.parse("2026-11-10T01:00:00Z");

    // DB 대신 계정을 담아 둘 메모리 목록
    private final List<Account> accountRows = new ArrayList<>();
    // DB 대신 소셜 연결(제공자·사용자 번호)을 담아 둘 메모리 목록
    private final List<SocialIdentity> identityRows = new ArrayList<>();
    // (도구) mock(종류) = 진짜 대신 가짜 객체를 만든다. 아래에서 메모리 목록을 쓰도록 답을 정해 준다
    // 계정 저장소(가짜)
    private final AccountRepository accounts = mock(AccountRepository.class);
    // 소셜 연결 저장소(가짜)
    private final SocialIdentityRepository identities = mock(SocialIdentityRepository.class);
    // 로그인 토큰 발급 서비스(가짜)
    private final LoginService loginService = mock(LoginService.class);
    // 무작위 값 만들기 도구(가짜). 아무도 모르는 비밀번호 값을 정해 두려고
    private final SecureTokens secureTokens = mock(SecureTokens.class);
    // 시험할 소셜 로그인 서비스(테스트마다 새로 만든다)
    private SocialLoginService service;

    // (도구) @BeforeEach = 각 테스트 전에 매번 먼저 실행할 준비 코드. @SuppressWarnings = 옛 도구(NoOpPasswordEncoder) 사용 경고를 숨긴다
    @BeforeEach
    @SuppressWarnings("deprecation")
    void setUp() {
        // (도구) given(가짜.메서드()).willReturn(결과) = when().thenReturn()과 같은 뜻. "이 호출이 오면 이 값을 돌려줘"
        // 무작위 값을 달라고 하면 "random-unusable"을 주게 한다(소셜 가입자의 아무도 모르는 비밀번호)
        given(secureTokens.opaqueToken()).willReturn("random-unusable");
        // (도구) willAnswer(i -> ...) = 호출이 오면 그 코드를 돌려 답한다. i.getArgument(n) = 받은 n번째 값. any()·anyLong() = 아무 값이나
        // 이메일로 계정을 찾으면 메모리 목록에서 같은 이메일을 찾아 준다
        given(accounts.findByEmail(any())).willAnswer(i -> accountRows.stream()
                .filter(a -> i.getArgument(0).equals(a.getEmail())).findFirst());
        // 번호로 계정을 찾으면 메모리 목록에서 찾아 준다
        given(accounts.findById(anyLong())).willAnswer(i -> accountRows.stream()
                .filter(a -> a.getId().equals(i.getArgument(0))).findFirst());
        // 계정을 저장하면 번호를 붙여 메모리 목록에 넣는다
        given(accounts.saveAndFlush(any())).willAnswer(i -> add(i.getArgument(0)));
        // 제공자·사용자 번호로 연결을 찾으면 메모리 목록에서 찾아 준다
        given(identities.findByProviderAndSubject(any(), any())).willAnswer(i -> identityRows.stream()
                .filter(x -> x.getProvider() == i.getArgument(0) && x.getSubject().equals(i.getArgument(1)))
                .findFirst());
        // 계정 번호·제공자로 연결을 찾으면 메모리 목록에서 찾아 준다
        given(identities.findByAccountIdAndProvider(anyLong(), any())).willAnswer(i -> identityRows.stream()
                .filter(x -> x.getAccountId().equals(i.getArgument(0)) && x.getProvider() == i.getArgument(1))
                .findFirst());
        // 연결을 저장하면
        given(identities.save(any())).willAnswer(i -> {
            // 메모리 목록에 넣고
            identityRows.add(i.getArgument(0));
            // 저장한 연결을 그대로 돌려준다
            return i.getArgument(0);
        });
        // (도구) willAnswer(...).given(가짜).메서드(...) = 반환값 없는(void) 메서드에 답을 정하는 순서
        // 연결을 지우면 메모리 목록에서 뺀다
        willAnswer(i -> identityRows.remove(i.<SocialIdentity>getArgument(0)))
                .given(identities).delete(any());
        // 로그인 토큰을 발급하면 "refresh-for-계정ID" 리프레시 토큰과 그 계정 역할을 돌려준다(누구로 로그인했는지 알 수 있게)
        given(loginService.issueFor(any())).willAnswer(i -> new LoginResult(null, "refresh-for-"
                + i.<Account>getArgument(0).getPublicId(), i.<Account>getArgument(0).getRole()));
        // 가짜 저장소들, 그대로 저장하는 비밀번호 도구, 고정 시계로 서비스를 만든다
        service = new SocialLoginService(identities, accounts, loginService, NoOpPasswordEncoder.getInstance(),
                secureTokens, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    // [상황] 처음 온 깃허브 사용자(이메일 대문자 섞임)가 로그인한다.
    // [기대] 이메일을 소문자로 정리해 바로 사용 가능한 고객 계정을 만들고 로그인시킨다.
    //        비밀번호는 아무도 모르는 값으로 채우고 "비밀번호 정한 적 없음"으로 표시한다. 깃허브 연결도 저장한다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("처음 온 GitHub 사용자는 인증된 이메일로 ACTIVE 고객 계정이 만들어지고 바로 로그인된다")
    void newUserBecomesActiveCustomer() {
        // 실행: 처음 온 깃허브 사용자(번호 123, 대문자 섞인 이메일)로 로그인한다
        LoginResult result = service.login(new SocialProfile(SocialProvider.GITHUB, "123", "Dev@Example.com", "개발자"));

        // (도구) assertThat(값).hasSize(n) = 개수가 n개여야 통과하는 AssertJ 검사
        // 확인: 계정이 하나 만들어져야 한다
        assertThat(accountRows).hasSize(1);
        // 만들어진 계정을 꺼낸다
        Account created = accountRows.get(0);
        // (도구) isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 이메일이 소문자로 정리돼야 한다
        assertThat(created.getEmail()).isEqualTo("dev@example.com");
        // 확인: 역할이 고객이어야 한다
        assertThat(created.getRole()).isEqualTo(AccountRole.CUSTOMER);
        // 확인: 메일 인증 없이 바로 ACTIVE여야 한다(제공자가 이메일을 확인해 줌)
        assertThat(created.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        // 확인: 이름이 제공자에게 받은 이름이어야 한다
        assertThat(created.getName()).isEqualTo("개발자");
        // 확인: 비밀번호 칸이 아무도 모르는 무작위 값이어야 한다
        assertThat(created.getPasswordHash()).isEqualTo("random-unusable");
        // (도구) isFalse() = 값이 false여야 통과
        // 확인: "비밀번호 정한 적 없음"으로 표시돼야 한다
        assertThat(created.isPasswordSet()).isFalse();
        // (도구) singleElement().satisfies(검사) = 딱 하나만 있고 그 하나가 검사를 통과해야 한다
        // 확인: 소셜 연결이 하나 저장되고
        assertThat(identityRows).singleElement().satisfies(i -> {
            // 제공자가 깃허브여야 하며
            assertThat(i.getProvider()).isEqualTo(SocialProvider.GITHUB);
            // 사용자 번호가 123이어야 한다
            assertThat(i.getSubject()).isEqualTo("123");
        });
        // 확인: 새 계정으로 로그인 토큰이 발급돼야 한다
        assertThat(result.refreshToken()).isEqualTo("refresh-for-" + created.getPublicId());
    }

    // [상황] 카카오에서 인증된 이메일을 받지 못했다.
    // [기대] 가입시키지 않고 EMAIL_REQUIRED.
    @Test
    @DisplayName("인증된 이메일을 받지 못하면 가입시키지 않고 EMAIL_REQUIRED")
    void emailIsRequired() {
        // 준비: 이메일이 없는(null) 카카오 사용자 정보
        SocialProfile noEmail = new SocialProfile(SocialProvider.KAKAO, "9", null, "카카오");
        // (도구) assertThatThrownBy(() -> 코드) = 그 코드를 돌리면 예외가 나야 통과. extracting = 예외에서 값을 꺼내 검사
        // 실행+확인: 로그인하면
        assertThatThrownBy(() -> service.login(noEmail))
                // 소셜 로그인 예외가 나야 하고
                .isInstanceOf(SocialLoginException.class)
                // 그 오류 종류가
                .extracting(e -> ((SocialLoginException) e).error())
                // EMAIL_REQUIRED여야 한다
                .isEqualTo(SocialLoginError.EMAIL_REQUIRED);
        // (도구) isEmpty() = 비어 있어야 통과
        // 확인: 계정이 만들어지지 않았어야 한다
        assertThat(accountRows).isEmpty();
        // (도구) verify(가짜, never()).메서드(...) = 그 메서드가 한 번도 불리지 않았는지 확인
        // 확인: 로그인 토큰도 발급하지 않았어야 한다
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 같은 이메일로 가입만 하고 메일 인증을 안 한 계정이 있는데, 구글로 로그인한다.
    // [기대] 새 계정을 만들지 않고 그 계정에 연결하며, 구글이 이메일을 확인해 줬으니 인증 완료(ACTIVE)가 된다.
    //        이름은 원래 것을 유지하고, 남이 미리 정해 둔 비밀번호는 못 쓰게 바꾼다(계정 선점 공격 방지).
    @Test
    @DisplayName("같은 이메일로 가입했지만 메일 인증 전인 계정은 Google 로그인으로 인증이 끝나고 그 계정에 연결된다")
    void linksExistingPendingAccount() {
        // 준비: 같은 이메일로 가입만 하고 메일 인증 전(PENDING)인 계정을 넣어 둔다
        Account pending = add(Account.customer(NanoId.next(), "me@trace.test", "hash", "나", AccountStatus.PENDING, NOW));

        // 실행: 같은 이메일의 구글 계정으로 로그인한다
        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-1", "me@trace.test", "Google 이름"));

        // 확인: 새 계정을 만들지 않아 여전히 하나여야 한다
        assertThat(accountRows).hasSize(1);
        // 확인: 구글이 이메일을 확인해 줬으니 ACTIVE가 돼야 한다
        assertThat(pending.getStatus()).isEqualTo(AccountStatus.ACTIVE);
        // 확인: 이름은 원래 것을 유지해야 한다
        assertThat(pending.getName()).isEqualTo("나");
        // 확인: 남이 미리 정해 둔 비밀번호는 못 쓰게 무작위 값으로 바뀌어야 한다(계정 선점 공격 방지)
        assertThat(pending.getPasswordHash()).isEqualTo("random-unusable");
        // 확인: "비밀번호 정한 적 없음"으로 표시돼야 한다
        assertThat(pending.isPasswordSet()).isFalse();
        // 확인: 구글 연결이 하나 생기고 그 계정에 붙어야 한다
        assertThat(identityRows).singleElement().extracting(SocialIdentity::getAccountId).isEqualTo(pending.getId());
    }

    // [상황] 이미 사용 중인 계정에 같은 이메일의 구글 로그인을 연결한다.
    // [기대] 원래 비밀번호는 그대로 둔다.
    @Test
    @DisplayName("이미 ACTIVE인 계정에 연결할 때는 원래 비밀번호를 그대로 둔다")
    void activeAccountKeepsPassword() {
        // 준비: 같은 이메일의 사용 중(ACTIVE) 계정을 넣어 둔다
        Account active = add(Account.customer(NanoId.next(), "me@trace.test", "hash", "나", AccountStatus.ACTIVE, NOW));

        // 실행: 같은 이메일의 구글 계정으로 로그인한다
        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-1", "me@trace.test", "Google 이름"));

        // 확인: 원래 비밀번호가 그대로여야 한다
        assertThat(active.getPasswordHash()).isEqualTo("hash");
        // (도구) isTrue() = 값이 true여야 통과
        // 확인: "비밀번호 정함" 표시도 그대로여야 한다
        assertThat(active.isPasswordSet()).isTrue();
    }

    // [상황] 관리자 이메일과 같은 구글 계정으로 로그인한다.
    // [기대] 연결하지 않고 거부한다(관리자 권한을 소셜 로그인으로 얻지 못하게).
    @Test
    @DisplayName("관리자 이메일로 소셜 로그인하면 연결하지 않고 거부한다")
    void adminEmailIsRejected() {
        // 준비: 관리자 계정을 넣어 둔다
        add(Account.admin(NanoId.next(), "admin@trace.test", "hash", "관리자", NOW));

        // 준비: 관리자와 같은 이메일의 구글 사용자 정보
        SocialProfile adminProfile = new SocialProfile(SocialProvider.GOOGLE, "g-9", "admin@trace.test", "x");
        // 실행+확인: 로그인하면
        assertThatThrownBy(() -> service.login(adminProfile))
                // 소셜 로그인 예외가 나야 한다
                .isInstanceOf(SocialLoginException.class);
        // 확인: 관리자 계정에 연결을 붙이지 않았어야 한다
        assertThat(identityRows).isEmpty();
        // 확인: 로그인 토큰을 발급하지 않았어야 한다 = 소셜 로그인으로 관리자 권한을 얻지 못한다
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 관리자 계정에 이미 깃허브 연결이 붙어 있다.
    // [기대] 그래도 소셜 로그인은 거부한다.
    @Test
    @DisplayName("관리자 계정에 이미 붙은 연결이 있어도 소셜 로그인은 거부한다")
    void linkedAdminIsRejected() {
        // 준비: 관리자 계정을 넣어 둔다
        Account admin = add(Account.admin(NanoId.next(), "admin@trace.test", "hash", "관리자", NOW));
        // 준비: 그 관리자 계정에 깃허브 연결(번호 77)이 이미 붙어 있게 한다
        identityRows.add(new SocialIdentity(admin.getId(), SocialProvider.GITHUB, "77", "admin@trace.test", NOW));

        // 준비: 그 깃허브 사용자 정보
        SocialProfile linkedProfile = new SocialProfile(SocialProvider.GITHUB, "77", "admin@trace.test", "x");
        // 실행+확인: 로그인하면
        assertThatThrownBy(() -> service.login(linkedProfile))
                // 소셜 로그인 예외가 나야 한다
                .isInstanceOf(SocialLoginException.class);
        // 확인: 로그인 토큰을 발급하지 않았어야 한다
        verify(loginService, never()).issueFor(any());
    }

    // [상황] 깃허브로 가입한 뒤 깃허브 쪽 이메일이 바뀌어서 다시 로그인한다.
    // [기대] 깃허브 사용자 번호로 찾아 같은 TRACE 계정으로 로그인된다.
    @Test
    @DisplayName("한 번 연결된 제공자 계정은 제공자 쪽 이메일이 바뀌어도 같은 TRACE 계정으로 로그인된다")
    void linkedIdentityWinsOverEmail() {
        // 준비: 깃허브 번호 123·이메일 old로 처음 로그인해 가입한다
        service.login(new SocialProfile(SocialProvider.GITHUB, "123", "old@example.com", "개발자"));
        // 그 계정 ID를 기억해 둔다
        String firstId = accountRows.get(0).getPublicId();

        // 실행: 같은 번호인데 이메일이 new로 바뀐 채 다시 로그인한다
        LoginResult again = service.login(new SocialProfile(SocialProvider.GITHUB, "123", "new@example.com", "개발자"));

        // 확인: 새 계정이 생기지 않아야 한다
        assertThat(accountRows).hasSize(1);
        // 확인: 처음 계정으로 로그인돼야 한다 = 이메일보다 제공자 번호로 찾는다
        assertThat(again.refreshToken()).isEqualTo("refresh-for-" + firstId);
    }

    // [상황] 네이버로 가입한 고객이 탈퇴한 뒤 같은 네이버 계정으로 다시 온다.
    // [기대] 새 고객 계정으로 가입되고, 네이버 연결은 새 계정으로 옮겨진다.
    @Test
    @DisplayName("탈퇴한 계정에 붙어 있던 제공자 계정으로 다시 오면 새 고객 계정으로 가입된다")
    void withdrawnAccountStartsOver() {
        // 준비: 네이버로 가입한다
        service.login(new SocialProfile(SocialProvider.NAVER, "n-1", "nv@example.com", "네이버"));
        // 그 계정을 꺼내
        Account first = accountRows.get(0);
        // 준비: 탈퇴시킨다
        first.withdraw(NOW);

        // 실행: 같은 네이버 계정으로 다시 로그인한다
        service.login(new SocialProfile(SocialProvider.NAVER, "n-1", "nv@example.com", "네이버"));

        // 확인: 새 고객 계정이 하나 더 만들어져 2개여야 한다
        assertThat(accountRows).hasSize(2);
        // 확인: 네이버 연결은 하나뿐이고 그 연결이
        assertThat(identityRows).singleElement().extracting(SocialIdentity::getAccountId)
                // 새 계정에 붙어 있어야 한다(옮겨짐)
                .isEqualTo(accountRows.get(1).getId());
    }

    // [상황] 구글에서 이름을 받지 못했다.
    // [기대] 이메일 앞부분(kim)을 이름으로 쓴다.
    @Test
    @DisplayName("이름을 받지 못하면 이메일 앞부분을 이름으로 쓴다")
    void nameFallsBackToEmailLocalPart() {
        // 실행: 이름 없이(null) 구글로 로그인한다
        service.login(new SocialProfile(SocialProvider.GOOGLE, "g-2", "kim@example.com", null));
        // 확인: 이메일 앞부분 kim이 이름으로 들어가야 한다
        assertThat(accountRows.get(0).getName()).isEqualTo("kim");
    }

    // 도우미: 메모리 목록에 계정을 넣고 번호를 붙인다.
    private Account add(Account account) {
        try {
            // (도구) 리플렉션 = 감춰진(private) 칸을 테스트에서 직접 바꾸는 방법. DB가 붙여 주는 번호를 흉내 내려고 쓴다
            // 계정의 감춰진 번호(id) 칸을 찾는다
            var field = Account.class.getDeclaredField("id");
            // 감춰진 칸을 바꿀 수 있게 연다
            field.setAccessible(true);
            // 목록 순서대로 1, 2, … 번호를 붙인다
            field.set(account, (long) accountRows.size() + 1);
        } catch (ReflectiveOperationException e) {
            // 실패하면 시험을 바로 멈추게 예외로 바꿔 던진다
            throw new IllegalStateException(e);
        }
        // 메모리 목록에 계정을 넣는다
        accountRows.add(account);
        // 번호가 붙은 계정을 돌려준다
        return account;
    }
}
