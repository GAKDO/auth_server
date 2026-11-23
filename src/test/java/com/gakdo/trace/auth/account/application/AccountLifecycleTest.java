// 이 파일이 확인하는 것: 고객 계정의 한살이(가입 → 이메일 인증 → 비밀번호 재설정 → 탈퇴) 규칙.
// DB 대신 메모리 목록을 쓰고, 시계를 마음대로 돌려 만료를 시험한다. 메일은 실제로 보내지 않는다.

package com.gakdo.trace.auth.account.application;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.BDDMockito.given;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.EmailToken;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.account.domain.EmailTokenRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.domain.RateLimitedException;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.config.EmailCodeProperties;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/** 가입 → 메일 인증 → 재설정 → 탈퇴를 DB 없이(메모리 저장소) 수용 기준대로 확인한다. */
class AccountLifecycleTest {

    private static final Instant T0 = Instant.parse("2026-11-06T00:00:00Z");

    private final MutableClock clock = new MutableClock(T0);
    private final List<Account> accountRows = new ArrayList<>();
    private final List<EmailToken> tokenRows = new ArrayList<>();
    private final AccountRepository accounts = mock(AccountRepository.class);
    private final EmailTokenRepository tokens = mock(EmailTokenRepository.class);
    private final SecureTokens secureTokens = mock(SecureTokens.class);
    private final CodeMailer mailer = mock(CodeMailer.class);
    private final ResendGuard guard = mock(ResendGuard.class);
    private final RefreshTokenStore refreshTokens = mock(RefreshTokenStore.class);
    private final com.gakdo.trace.auth.social.domain.SocialIdentityRepository socialIdentities =
            mock(com.gakdo.trace.auth.social.domain.SocialIdentityRepository.class);
    @SuppressWarnings("deprecation")
    private final PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
    private final EmailCodeProperties props = new EmailCodeProperties(Duration.ofMinutes(10), 5,
            Duration.ofSeconds(60), "team@trace.test");
    private final AtomicReference<String> sentCode = new AtomicReference<>();

    private SignupService signup;
    private PasswordResetService reset;
    private WithdrawService withdraw;

    @BeforeEach
    void setUp() {
        given(accounts.existsByEmail(any())).willAnswer(i -> find(i.getArgument(0)).isPresent());
        given(accounts.findByEmail(any())).willAnswer(i -> find(i.getArgument(0)));
        given(accounts.findByEmailForUpdate(any())).willAnswer(i -> find(i.getArgument(0)));
        given(accounts.findByPublicId(any())).willAnswer(i -> accountRows.stream()
                .filter(a -> a.getPublicId().equals(i.getArgument(0))).findFirst());
        given(accounts.saveAndFlush(any())).willAnswer(i -> {
            Account a = i.getArgument(0);
            setId(a, (long) accountRows.size() + 1);
            accountRows.add(a);
            return a;
        });
        given(tokens.save(any())).willAnswer(i -> {
            tokenRows.add(i.getArgument(0));
            return i.getArgument(0);
        });
        given(tokens.findByAccountIdAndPurposeAndUsedAtIsNull(any(), any())).willAnswer(i -> tokenRows.stream()
                .filter(t -> t.getAccountId().equals(i.getArgument(0)) && t.getUsedAt() == null).toList());
        given(tokens.findFirstByAccountIdAndPurposeAndUsedAtIsNullOrderByCreatedAtDescIdDesc(any(), any()))
                .willAnswer(i -> tokenRows.stream()
                        .filter(t -> t.getAccountId().equals(i.getArgument(0)) && t.getUsedAt() == null)
                        .max(Comparator.comparingInt(tokenRows::indexOf)));
        given(guard.tryAcquire(any(), any())).willReturn(0L);
        given(secureTokens.sixDigitCode()).willReturn("123456", "234567", "345678", "456789");
        org.mockito.Mockito.doAnswer(i -> {
            sentCode.set(i.getArgument(2));
            return null;
        }).when(mailer).send(any(), any(), any());

        EmailCodeService codes = new EmailCodeService(tokens, secureTokens, mailer, props, clock);
        signup = new SignupService(accounts, encoder, codes, guard, clock);
        reset = new PasswordResetService(accounts, tokens, encoder, codes, guard, refreshTokens, clock);
        withdraw = new WithdrawService(accounts, encoder, refreshTokens, socialIdentities, clock);
    }

    // [상황] 새 고객이 가입하고, 메일로 받은 6자리 코드를 넣는다.
    // [기대] 가입 직후는 인증 대기(PENDING), 코드를 넣으면 사용 가능(ACTIVE).
    @Test
    @DisplayName("가입하면 PENDING 계정과 6자리 코드 메일이 생기고, 코드를 넣으면 ACTIVE가 된다")
    void signupThenVerify() {
        SignupResult result = signup.signup(" Renter@Trace.test ", "pass-1234", "홍길동", true);

        assertThat(result.status()).isEqualTo(AccountStatus.PENDING);
        assertThat(sentCode.get()).isEqualTo("123456");
        assertThat(tokenRows.get(0).getCodeHash()).doesNotContain("123456"); // 해시만 저장
        signup.verify("renter@trace.test", "123456");
        assertThat(accountRows.get(0).getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 개인정보 동의 없이 가입하고, 이미 가입한 이메일로 다시 가입한다.
    // [기대] 동의 없음 400 CONSENT_REQUIRED, 중복 이메일 409.
    @Test
    @DisplayName("동의 없이 가입하면 400 CONSENT_REQUIRED, 같은 이메일로 다시 가입하면 409다")
    void consentAndDuplicate() {
        assertThatThrownBy(() -> signup.signup("a@trace.test", "pass-1234", "가", false))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CONSENT_REQUIRED);
        signup.signup("a@trace.test", "pass-1234", "가", true);
        assertThatThrownBy(() -> signup.signup("A@trace.test", "pass-1234", "가", true))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS);
    }

    // [상황] 인증 코드를 5번 틀린 뒤 맞는 코드를 넣는다. 다른 경우에는 10분이 지난 뒤 넣는다.
    // [기대] 5번 틀리면 코드가 폐기되어 맞는 코드도 410, 10분이 지나도 410(코드 맞히기 방지).
    @Test
    @DisplayName("코드를 5번 틀리면 폐기되어 맞는 코드도 410이고, 10분이 지나도 410이다")
    void attemptsAndExpiry() {
        signup.signup("b@trace.test", "pass-1234", "나", true);
        for (int remaining = 4; remaining >= 0; remaining--) {
            int expected = remaining;
            assertThatThrownBy(() -> signup.verify("b@trace.test", "000000"))
                    .isInstanceOf(CodeInvalidException.class)
                    .extracting(e -> ((CodeInvalidException) e).remainingAttempts()).isEqualTo(expected);
        }
        assertThatThrownBy(() -> signup.verify("b@trace.test", "123456"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);

        signup.resend("b@trace.test");
        clock.advance(Duration.ofMinutes(10));
        assertThatThrownBy(() -> signup.verify("b@trace.test", "234567"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);
    }

    // [상황] 인증 메일을 다시 보내 달라고 하고, 60초 안에 또 요청한다.
    // [기대] 다시 보내면 앞 코드는 못 쓰고 새 코드만 된다. 60초 안 재요청은 429 RESEND_TOO_SOON.
    @Test
    @DisplayName("재발송하면 앞 코드는 쓸 수 없고, 60초 안 재발송은 429 RESEND_TOO_SOON이다")
    void resendReplacesAndThrottles() {
        signup.signup("c@trace.test", "pass-1234", "다", true);
        signup.resend("c@trace.test");
        assertThatThrownBy(() -> signup.verify("c@trace.test", "123456")).isInstanceOf(CodeInvalidException.class);
        signup.verify("c@trace.test", "234567");

        given(guard.tryAcquire(EmailTokenPurpose.VERIFY, "c@trace.test")).willReturn(37L);
        assertThatThrownBy(() -> signup.resend("c@trace.test"))
                .isInstanceOf(RateLimitedException.class)
                .extracting(e -> ((RateLimitedException) e).retryAfterSeconds()).isEqualTo(37L);
    }

    // [상황] 가입하지 않은 이메일로 재발송·비밀번호 재설정을 요청한다.
    // [기대] 오류 없이 끝나고 메일도 보내지 않는다(어떤 이메일이 가입했는지 알아내지 못하게).
    @Test
    @DisplayName("없는 이메일의 재발송·재설정 요청도 오류 없이 끝나고 메일은 보내지 않는다")
    void unknownEmailIsSilent() {
        signup.resend("nobody@trace.test");
        reset.requestReset("nobody@trace.test");
        verify(mailer, never()).send(any(), any(), any());
        assertThatThrownBy(() -> reset.reset("nobody@trace.test", "123456", "new-pass-5678"))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);
    }

    // [상황] 비밀번호 재설정 코드로 비밀번호를 바꾼다.
    // [기대] 비밀번호가 바뀌고, 그 계정의 리프레시 토큰이 모두 지워져 다른 기기 로그인도 풀린다.
    @Test
    @DisplayName("재설정하면 비밀번호가 바뀌고 그 계정의 리프레시 토큰이 모두 지워진다")
    void resetPassword() {
        signup.signup("d@trace.test", "pass-1234", "라", true);
        signup.verify("d@trace.test", "123456");
        reset.requestReset("d@trace.test");
        reset.reset("d@trace.test", sentCode.get(), "new-pass-5678");

        Account account = accountRows.get(0);
        assertThat(account.getPasswordHash()).isEqualTo("new-pass-5678");
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 한 계정으로 재설정 코드를 하루에 6번 이상 요청한다.
    // [기대] 하루 5번까지만 보낸다(코드를 계속 바꿔 가며 맞혀 보는 공격 방지).
    @Test
    @DisplayName("재설정 코드는 계정당 하루 5번까지만 보내 코드를 계속 바꿔 가며 맞혀 볼 수 없다")
    void resetCodesPerDayAreCapped() {
        signup.signup("f@trace.test", "pass-1234", "바", true);
        signup.verify("f@trace.test", "123456");
        org.mockito.Mockito.clearInvocations(mailer);
        given(tokens.countByAccountIdAndPurposeAndCreatedAtAfter(any(), any(), any()))
                .willReturn((long) PasswordResetService.MAX_CODES_PER_DAY - 1, (long) PasswordResetService.MAX_CODES_PER_DAY);
        reset.requestReset("f@trace.test");
        reset.requestReset("f@trace.test");
        verify(mailer, org.mockito.Mockito.times(1)).send(any(), any(), any());
        verify(tokens, org.mockito.Mockito.times(2)).countByAccountIdAndPurposeAndCreatedAtAfter(accountRows.get(0).getId(),
                EmailTokenPurpose.RESET, T0.minus(Duration.ofHours(24)));
    }

    // [상황] 고객이 비밀번호를 넣고 탈퇴한다. 틀린 비밀번호로도 해 본다.
    // [기대] 이메일·이름·비밀번호가 지워지고 WITHDRAWN 상태가 된다. 틀린 비밀번호면 401.
    @Test
    @DisplayName("탈퇴하면 이메일·이름·비밀번호가 지워지고 WITHDRAWN이 되며, 비밀번호가 틀리면 401이다")
    void withdrawAccount() {
        signup.signup("e@trace.test", "pass-1234", "마", true);
        signup.verify("e@trace.test", "123456");
        Account account = accountRows.get(0);

        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "wrong-pass", T0))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        withdraw.withdraw(account.getPublicId(), "pass-1234", null);

        assertThat(account.getStatus()).isEqualTo(AccountStatus.WITHDRAWN);
        assertThat(account.getEmail()).isNull();
        assertThat(account.getName()).isNull();
        assertThat(account.getPasswordHash()).isNull();
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 구글·깃허브로만 가입해 비밀번호를 정한 적 없는 고객이 로그인 10분 안에 탈퇴한다.
    // [기대] 비밀번호 없이 탈퇴되고 소셜 연결도 지워진다.
    @Test
    @DisplayName("비밀번호를 정한 적 없는 계정은 로그인한 지 10분 안이면 비밀번호 없이 탈퇴하고, 소셜 연결도 지워진다")
    void socialAccountWithdrawsWithoutPassword() {
        Account account = socialOnlyAccount("s@trace.test");
        clock.advance(Duration.ofMinutes(9));

        withdraw.withdraw(account.getPublicId(), null, T0);

        assertThat(account.getStatus()).isEqualTo(AccountStatus.WITHDRAWN);
        verify(socialIdentities).deleteByAccountId(account.getId());
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 같은 소셜 고객이 로그인한 지 10분이 지났거나 로그인 시각을 모르는 상태로 탈퇴한다.
    // [기대] 403 REAUTH_REQUIRED(다시 로그인하세요), 탈퇴되지 않는다(남이 켜 둔 화면으로 탈퇴 방지).
    @Test
    @DisplayName("비밀번호 없는 탈퇴는 로그인한 지 10분이 지났거나 로그인 시각을 모르면 403 REAUTH_REQUIRED이고 탈퇴되지 않는다")
    void passwordlessWithdrawNeedsRecentLogin() {
        Account account = socialOnlyAccount("old@trace.test");
        clock.advance(Duration.ofMinutes(11));

        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.REAUTH_REQUIRED);
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "", null))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.REAUTH_REQUIRED);
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 비밀번호로 가입한 고객(소셜도 연결됨)이 비밀번호 없이 탈퇴하려 한다.
    // [기대] 401, 탈퇴되지 않는다.
    @Test
    @DisplayName("비밀번호를 정한 계정은 소셜이 자동 연결돼 있어도 비밀번호를 빼면 401이고 탈퇴되지 않는다")
    void passwordAccountNeedsPassword() {
        signup.signup("p@trace.test", "pass-1234", "비번", true);
        signup.verify("p@trace.test", "123456");
        Account account = accountRows.get(0);
        given(socialIdentities.findByAccountId(account.getId())).willReturn(java.util.List.of(
                new com.gakdo.trace.auth.social.domain.SocialIdentity(account.getId(),
                        com.gakdo.trace.auth.social.domain.SocialProvider.GOOGLE, "g-1", "p@trace.test", T0)));

        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "", T0))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 소셜 가입 고객이 비밀번호를 재설정해 비밀번호를 갖게 된다.
    // [기대] 그다음부터는 탈퇴에 비밀번호가 필요하다.
    @Test
    @DisplayName("소셜 가입 계정도 비밀번호를 재설정하면 그다음부터는 탈퇴에 비밀번호가 필요하다")
    void resetPasswordMakesPasswordSet() {
        Account account = socialOnlyAccount("r@trace.test");
        assertThat(account.isPasswordSet()).isFalse();

        account.changePassword("new-pass-1234", T0);

        assertThat(account.isPasswordSet()).isTrue();
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
    }

    /** 소셜 가입처럼 아무도 모르는 비밀번호를 가진 ACTIVE 계정. */
    // 도우미: 소셜 가입처럼 아무도 모르는 비밀번호를 가진 사용 가능 계정을 만든다.
    private Account socialOnlyAccount(String email) {
        signup.signup(email, "pass-1234", "소셜", true);
        signup.verify(email, "123456");
        Account account = accountRows.get(0);
        account.replaceWithUnusablePassword("unusable", T0);
        return account;
    }

    private Optional<Account> find(String email) {
        return accountRows.stream().filter(a -> email != null && email.equals(a.getEmail())).findFirst();
    }

    private static void setId(Account account, long id) {
        try {
            var field = Account.class.getDeclaredField("id");
            field.setAccessible(true);
            field.set(account, id);
        } catch (ReflectiveOperationException e) {
            throw new IllegalStateException(e);
        }
    }

    /** 만료를 시험하려고 시간을 앞으로 돌릴 수 있는 시계. */
    // 도우미: 시간을 앞으로 돌릴 수 있는 가짜 시계(10분 만료 등을 시험).
    static final class MutableClock extends Clock {
        private Instant now;

        MutableClock(Instant now) {
            this.now = now;
        }

        void advance(Duration d) {
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            return this;
        }

        @Override
        public Instant instant() {
            return now;
        }
    }
}
