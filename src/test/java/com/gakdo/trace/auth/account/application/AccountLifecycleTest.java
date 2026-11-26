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

    // 시험 시작 시각을 고정한다
    private static final Instant T0 = Instant.parse("2026-11-06T00:00:00Z");

    // 시간을 앞으로 돌릴 수 있는 가짜 시계(아래 도우미). 10분 만료 등을 기다리지 않고 시험하려고
    private final MutableClock clock = new MutableClock(T0);
    // DB 대신 계정을 담아 둘 메모리 목록
    private final List<Account> accountRows = new ArrayList<>();
    // DB 대신 이메일 코드를 담아 둘 메모리 목록
    private final List<EmailToken> tokenRows = new ArrayList<>();
    // (도구) mock(종류) = 진짜 대신 가짜 객체를 만든다. 아래 setUp에서 메모리 목록을 쓰도록 답을 정해 준다
    // 계정 저장소(가짜)
    private final AccountRepository accounts = mock(AccountRepository.class);
    // 이메일 코드 저장소(가짜)
    private final EmailTokenRepository tokens = mock(EmailTokenRepository.class);
    // 6자리 코드 만들기 도구(가짜). 어떤 코드가 나올지 정해 두려고
    private final SecureTokens secureTokens = mock(SecureTokens.class);
    // 코드 메일 보내기(가짜). 실제로 보내지 않고 보낸 코드만 가로챈다
    private final CodeMailer mailer = mock(CodeMailer.class);
    // 재발송 너무 잦음 막기(가짜)
    private final ResendGuard guard = mock(ResendGuard.class);
    // 리프레시 토큰 저장소(가짜). 모두 지웠는지 확인하려고
    private final RefreshTokenStore refreshTokens = mock(RefreshTokenStore.class);
    // 소셜 연결 저장소(가짜)
    private final com.gakdo.trace.auth.social.domain.SocialIdentityRepository socialIdentities =
            mock(com.gakdo.trace.auth.social.domain.SocialIdentityRepository.class);
    // 비밀번호를 그대로 저장하는 시험용 도구(해시 대신 원문 비교로 확인하기 쉽게). @SuppressWarnings = 옛 도구 경고 숨김
    @SuppressWarnings("deprecation")
    private final PasswordEncoder encoder = NoOpPasswordEncoder.getInstance();
    // 코드 유효 10분, 시도 5번, 재발송 간격 60초, 보내는 사람 주소 설정
    private final EmailCodeProperties props = new EmailCodeProperties(Duration.ofMinutes(10), 5,
            Duration.ofSeconds(60), "team@trace.test");
    // 메일로 나간 마지막 코드를 담아 둘 상자
    private final AtomicReference<String> sentCode = new AtomicReference<>();

    // 가입·인증 서비스(테스트마다 새로)
    private SignupService signup;
    // 비밀번호 재설정 서비스
    private PasswordResetService reset;
    // 탈퇴 서비스
    private WithdrawService withdraw;

    // (도구) @BeforeEach = 각 테스트 전에 매번 먼저 실행할 준비 코드
    @BeforeEach
    void setUp() {
        // (도구) given(가짜.메서드(조건)).willAnswer(i -> ...) = 호출이 오면 그 코드를 돌려 답한다. i.getArgument(n) = 받은 n번째 값. any() = 아무 값이나
        // 이메일로 계정이 있는지 물으면 메모리 목록에서 찾아 답한다
        given(accounts.existsByEmail(any())).willAnswer(i -> find(i.getArgument(0)).isPresent());
        // 이메일로 계정을 찾으면 메모리 목록에서 찾아 준다
        given(accounts.findByEmail(any())).willAnswer(i -> find(i.getArgument(0)));
        // 고치려고 찾는 경우도 같게 답한다
        given(accounts.findByEmailForUpdate(any())).willAnswer(i -> find(i.getArgument(0)));
        // 공개 ID로 찾으면 메모리 목록에서 찾아 준다
        given(accounts.findByPublicId(any())).willAnswer(i -> accountRows.stream()
                .filter(a -> a.getPublicId().equals(i.getArgument(0))).findFirst());
        // 계정을 저장하면
        given(accounts.saveAndFlush(any())).willAnswer(i -> {
            // 받은 계정을 꺼내
            Account a = i.getArgument(0);
            // DB처럼 1, 2, … 번호를 붙이고
            setId(a, (long) accountRows.size() + 1);
            // 메모리 목록에 넣고
            accountRows.add(a);
            // 그 계정을 돌려준다
            return a;
        });
        // 코드를 저장하면
        given(tokens.save(any())).willAnswer(i -> {
            // 메모리 목록에 넣고
            tokenRows.add(i.getArgument(0));
            // 그 코드를 돌려준다
            return i.getArgument(0);
        });
        // 그 계정의 아직 안 쓴 코드 목록을 달라고 하면 메모리에서 골라 준다
        given(tokens.findByAccountIdAndPurposeAndUsedAtIsNull(any(), any())).willAnswer(i -> tokenRows.stream()
                .filter(t -> t.getAccountId().equals(i.getArgument(0)) && t.getUsedAt() == null).toList());
        // 그 계정의 안 쓴 코드 중 가장 최근 것을 달라고 하면 목록 맨 뒤 것을 준다
        given(tokens.findFirstByAccountIdAndPurposeAndUsedAtIsNullOrderByCreatedAtDescIdDesc(any(), any()))
                .willAnswer(i -> tokenRows.stream()
                        .filter(t -> t.getAccountId().equals(i.getArgument(0)) && t.getUsedAt() == null)
                        .max(Comparator.comparingInt(tokenRows::indexOf)));
        // (도구) willReturn(값) = 그 값을 돌려주게 한다
        // 재발송 막기는 기본으로 0(막지 않음)을 돌려주게 한다
        given(guard.tryAcquire(any(), any())).willReturn(0L);
        // 코드를 뽑을 때마다 123456, 234567, 345678, 456789 순서로 나오게 한다
        given(secureTokens.sixDigitCode()).willReturn("123456", "234567", "345678", "456789");
        // (도구) doAnswer(코드).when(가짜).메서드(...) = 반환값 없는(void) 메서드가 불리면 그 코드를 돌리게 한다
        // 메일 보내기가 불리면
        org.mockito.Mockito.doAnswer(i -> {
            // 세 번째 값(코드)을 상자에 담고
            sentCode.set(i.getArgument(2));
            // 돌려줄 값은 없다
            return null;
        }).when(mailer).send(any(), any(), any());

        // 가짜 저장소·메일·설정·시계로 이메일 코드 서비스를 만든다
        EmailCodeService codes = new EmailCodeService(tokens, secureTokens, mailer, props, clock);
        // 가입 서비스를 만든다
        signup = new SignupService(accounts, encoder, codes, guard, clock);
        // 재설정 서비스를 만든다
        reset = new PasswordResetService(accounts, tokens, encoder, codes, guard, refreshTokens, clock);
        // 탈퇴 서비스를 만든다
        withdraw = new WithdrawService(accounts, encoder, refreshTokens, socialIdentities, clock);
    }

    // [상황] 새 고객이 가입하고, 메일로 받은 6자리 코드를 넣는다.
    // [기대] 가입 직후는 인증 대기(PENDING), 코드를 넣으면 사용 가능(ACTIVE).
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("가입하면 PENDING 계정과 6자리 코드 메일이 생기고, 코드를 넣으면 ACTIVE가 된다")
    void signupThenVerify() {
        // 실행: 앞뒤 공백·대문자가 섞인 이메일로 동의하고 가입한다
        SignupResult result = signup.signup(" Renter@Trace.test ", "pass-1234", "홍길동", true);

        // (도구) assertThat(값).isEqualTo(기대값) = "값이 기대값과 같아야 한다"를 확인하는 AssertJ 도구
        // 확인: 가입 직후는 인증 대기(PENDING)여야 한다
        assertThat(result.status()).isEqualTo(AccountStatus.PENDING);
        // 확인: 메일로 첫 코드 123456이 나갔어야 한다
        assertThat(sentCode.get()).isEqualTo("123456");
        // (도구) doesNotContain(글자) = 그 글자가 없어야 통과
        // 확인: 저장된 코드 칸에 원문 숫자가 없어야 한다
        assertThat(tokenRows.get(0).getCodeHash()).doesNotContain("123456"); // 해시만 저장
        // 실행: 정리된 소문자 이메일과 그 코드로 인증한다
        signup.verify("renter@trace.test", "123456");
        // 확인: 계정이 사용 가능(ACTIVE)이 돼야 한다
        assertThat(accountRows.get(0).getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 개인정보 동의 없이 가입하고, 이미 가입한 이메일로 다시 가입한다.
    // [기대] 동의 없음 400 CONSENT_REQUIRED, 중복 이메일 409.
    //        ※ 응답 코드: 400 = 요청 내용이 형식에 맞지 않음, 409 = 지금 상태와 맞지 않아 거절(이미 있음·순서 어긋남 등)
    @Test
    @DisplayName("동의 없이 가입하면 400 CONSENT_REQUIRED, 같은 이메일로 다시 가입하면 409다")
    void consentAndDuplicate() {
        // (도구) assertThatThrownBy(() -> 코드) = 그 코드를 돌리면 예외가 나야 통과. extracting = 예외에서 값을 꺼내 검사
        // 실행+확인: 개인정보 동의 없이(false) 가입하면
        assertThatThrownBy(() -> signup.signup("a@trace.test", "pass-1234", "가", false))
                // 오류 코드가 CONSENT_REQUIRED(400)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CONSENT_REQUIRED);
        // 준비: 같은 이메일로 정상 가입한다
        signup.signup("a@trace.test", "pass-1234", "가", true);
        // 실행+확인: 대문자만 다른 같은 이메일로 다시 가입하면
        assertThatThrownBy(() -> signup.signup("A@trace.test", "pass-1234", "가", true))
                // 오류 코드가 EMAIL_ALREADY_EXISTS(409)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.EMAIL_ALREADY_EXISTS);
    }

    // [상황] 인증 코드를 5번 틀린 뒤 맞는 코드를 넣는다. 다른 경우에는 10분이 지난 뒤 넣는다.
    // [기대] 5번 틀리면 코드가 폐기되어 맞는 코드도 410, 10분이 지나도 410(코드 맞히기 방지).
    //        ※ 응답 코드: 410 = 이미 쓰였거나 만료되어 더는 쓸 수 없음
    @Test
    @DisplayName("코드를 5번 틀리면 폐기되어 맞는 코드도 410이고, 10분이 지나도 410이다")
    void attemptsAndExpiry() {
        // 준비: 가입해 코드 123456을 받는다
        signup.signup("b@trace.test", "pass-1234", "나", true);
        // 남은 횟수 4, 3, 2, 1, 0을 차례로 확인하며 5번 틀린다
        for (int remaining = 4; remaining >= 0; remaining--) {
            // 람다 안에서 쓰려고 지금 기대하는 남은 횟수를 따로 담는다
            int expected = remaining;
            // 실행+확인: 틀린 코드로 인증하면
            assertThatThrownBy(() -> signup.verify("b@trace.test", "000000"))
                    // (도구) isInstanceOf(종류) = 그 종류의 예외여야 통과
                    // "코드 틀림" 예외가 나야 하고
                    .isInstanceOf(CodeInvalidException.class)
                    // 남은 시도 횟수가 하나씩 줄어야 한다
                    .extracting(e -> ((CodeInvalidException) e).remainingAttempts()).isEqualTo(expected);
        }
        // 실행+확인: 5번 틀린 뒤 맞는 코드를 넣어도
        assertThatThrownBy(() -> signup.verify("b@trace.test", "123456"))
                // CODE_EXPIRED(410)여야 한다 = 코드가 폐기됨
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);

        // 준비: 다시 보내 새 코드 234567을 받는다
        signup.resend("b@trace.test");
        // 준비: 시계를 10분 앞으로 돌린다
        clock.advance(Duration.ofMinutes(10));
        // 실행+확인: 10분 지난 새 코드로 인증하면
        assertThatThrownBy(() -> signup.verify("b@trace.test", "234567"))
                // CODE_EXPIRED(410)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);
    }

    // [상황] 인증 메일을 다시 보내 달라고 하고, 60초 안에 또 요청한다.
    // [기대] 다시 보내면 앞 코드는 못 쓰고 새 코드만 된다. 60초 안 재요청은 429 RESEND_TOO_SOON.
    //        ※ 응답 코드: 429 = 요청이 너무 잦아 잠시 막음
    @Test
    @DisplayName("재발송하면 앞 코드는 쓸 수 없고, 60초 안 재발송은 429 RESEND_TOO_SOON이다")
    void resendReplacesAndThrottles() {
        // 준비: 가입해 코드 123456을 받는다
        signup.signup("c@trace.test", "pass-1234", "다", true);
        // 실행: 재발송해 새 코드 234567을 받는다
        signup.resend("c@trace.test");
        // 확인: 앞 코드 123456은 더는 맞지 않아야 한다
        assertThatThrownBy(() -> signup.verify("c@trace.test", "123456")).isInstanceOf(CodeInvalidException.class);
        // 확인: 새 코드로는 인증돼야 한다(예외가 나면 실패)
        signup.verify("c@trace.test", "234567");

        // 준비: 재발송 막기가 "37초 남음"을 돌려주게 한다 = 60초 안 재요청
        given(guard.tryAcquire(EmailTokenPurpose.VERIFY, "c@trace.test")).willReturn(37L);
        // 실행+확인: 다시 재발송하면
        assertThatThrownBy(() -> signup.resend("c@trace.test"))
                // "너무 잦음" 예외가 나야 하고
                .isInstanceOf(RateLimitedException.class)
                // 37초 뒤에 다시 하라고 알려야 한다
                .extracting(e -> ((RateLimitedException) e).retryAfterSeconds()).isEqualTo(37L);
    }

    // [상황] 가입하지 않은 이메일로 재발송·비밀번호 재설정을 요청한다.
    // [기대] 오류 없이 끝나고 메일도 보내지 않는다(어떤 이메일이 가입했는지 알아내지 못하게).
    @Test
    @DisplayName("없는 이메일의 재발송·재설정 요청도 오류 없이 끝나고 메일은 보내지 않는다")
    void unknownEmailIsSilent() {
        // 실행: 가입하지 않은 이메일로 재발송을 요청한다(예외가 나면 실패)
        signup.resend("nobody@trace.test");
        // 실행: 같은 이메일로 비밀번호 재설정 코드를 요청한다
        reset.requestReset("nobody@trace.test");
        // (도구) verify(가짜, never()).메서드(...) = 그 메서드가 한 번도 불리지 않았는지 확인
        // 확인: 메일을 보내지 않았어야 한다 = 어떤 이메일이 가입했는지 알아낼 수 없다
        verify(mailer, never()).send(any(), any(), any());
        // 실행+확인: 그 이메일로 재설정하면
        assertThatThrownBy(() -> reset.reset("nobody@trace.test", "123456", "new-pass-5678"))
                // 없는 계정도 "코드 만료"와 같은 오류여야 한다(가입 여부를 숨김)
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.CODE_EXPIRED);
    }

    // [상황] 비밀번호 재설정 코드로 비밀번호를 바꾼다.
    // [기대] 비밀번호가 바뀌고, 그 계정의 리프레시 토큰이 모두 지워져 다른 기기 로그인도 풀린다.
    @Test
    @DisplayName("재설정하면 비밀번호가 바뀌고 그 계정의 리프레시 토큰이 모두 지워진다")
    void resetPassword() {
        // 준비: 가입한다
        signup.signup("d@trace.test", "pass-1234", "라", true);
        // 준비: 인증한다
        signup.verify("d@trace.test", "123456");
        // 준비: 재설정 코드를 요청한다
        reset.requestReset("d@trace.test");
        // 실행: 메일로 받은 코드로 새 비밀번호를 정한다
        reset.reset("d@trace.test", sentCode.get(), "new-pass-5678");

        // 그 계정을 꺼낸다
        Account account = accountRows.get(0);
        // 확인: 비밀번호가 새것으로 바뀌어야 한다
        assertThat(account.getPasswordHash()).isEqualTo("new-pass-5678");
        // (도구) verify(가짜).메서드(값) = 그 값으로 (한 번) 불렸는지 확인
        // 확인: 그 계정의 리프레시 토큰을 모두 지웠어야 한다 = 다른 기기 로그인도 풀림
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 한 계정으로 재설정 코드를 하루에 6번 이상 요청한다.
    // [기대] 하루 5번까지만 보낸다(코드를 계속 바꿔 가며 맞혀 보는 공격 방지).
    @Test
    @DisplayName("재설정 코드는 계정당 하루 5번까지만 보내 코드를 계속 바꿔 가며 맞혀 볼 수 없다")
    void resetCodesPerDayAreCapped() {
        // 준비: 가입한다
        signup.signup("f@trace.test", "pass-1234", "바", true);
        // 준비: 인증한다
        signup.verify("f@trace.test", "123456");
        // (도구) clearInvocations(가짜) = 지금까지 불린 기록을 지운다. 이 뒤 메일 수만 세려고
        org.mockito.Mockito.clearInvocations(mailer);
        // 준비: 하루 동안 보낸 재설정 코드 수를 물으면 처음엔 한도-1(4), 다음엔 한도(5)라고 답하게 한다
        given(tokens.countByAccountIdAndPurposeAndCreatedAtAfter(any(), any(), any()))
                .willReturn((long) PasswordResetService.MAX_CODES_PER_DAY - 1, (long) PasswordResetService.MAX_CODES_PER_DAY);
        // 실행: 재설정 코드를 요청한다(한도 전이라 보냄)
        reset.requestReset("f@trace.test");
        // 실행: 한 번 더 요청한다(한도에 닿음)
        reset.requestReset("f@trace.test");
        // (도구) times(n) = 정확히 n번 불렸는지
        // 확인: 메일은 1번만 나갔어야 한다
        verify(mailer, org.mockito.Mockito.times(1)).send(any(), any(), any());
        // 확인: 두 번 모두 "그 계정·재설정 용도·지난 24시간" 기준으로 셌어야 한다
        verify(tokens, org.mockito.Mockito.times(2)).countByAccountIdAndPurposeAndCreatedAtAfter(accountRows.get(0).getId(),
                EmailTokenPurpose.RESET, T0.minus(Duration.ofHours(24)));
    }

    // [상황] 고객이 비밀번호를 넣고 탈퇴한다. 틀린 비밀번호로도 해 본다.
    // [기대] 이메일·이름·비밀번호가 지워지고 WITHDRAWN 상태가 된다. 틀린 비밀번호면 401.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("탈퇴하면 이메일·이름·비밀번호가 지워지고 WITHDRAWN이 되며, 비밀번호가 틀리면 401이다")
    void withdrawAccount() {
        // 준비: 가입한다
        signup.signup("e@trace.test", "pass-1234", "마", true);
        // 준비: 인증한다
        signup.verify("e@trace.test", "123456");
        // 그 계정을 꺼낸다
        Account account = accountRows.get(0);

        // 실행+확인: 틀린 비밀번호로 탈퇴하면
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "wrong-pass", T0))
                // INVALID_CREDENTIALS(401)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        // 실행: 맞는 비밀번호로 탈퇴한다
        withdraw.withdraw(account.getPublicId(), "pass-1234", null);

        // 확인: 상태가 WITHDRAWN이어야 한다
        assertThat(account.getStatus()).isEqualTo(AccountStatus.WITHDRAWN);
        // (도구) isNull() = 값이 없어야 통과
        // 확인: 이메일이 지워졌어야 한다
        assertThat(account.getEmail()).isNull();
        // 확인: 이름이 지워졌어야 한다
        assertThat(account.getName()).isNull();
        // 확인: 비밀번호가 지워졌어야 한다
        assertThat(account.getPasswordHash()).isNull();
        // 확인: 리프레시 토큰을 모두 지웠어야 한다
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 구글·깃허브로만 가입해 비밀번호를 정한 적 없는 고객이 로그인 10분 안에 탈퇴한다.
    // [기대] 비밀번호 없이 탈퇴되고 소셜 연결도 지워진다.
    @Test
    @DisplayName("비밀번호를 정한 적 없는 계정은 로그인한 지 10분 안이면 비밀번호 없이 탈퇴하고, 소셜 연결도 지워진다")
    void socialAccountWithdrawsWithoutPassword() {
        // 준비: 비밀번호를 정한 적 없는 소셜 가입 계정을 만든다
        Account account = socialOnlyAccount("s@trace.test");
        // 준비: 로그인(T0) 뒤 9분이 지나게 한다
        clock.advance(Duration.ofMinutes(9));

        // 실행: 비밀번호 없이, 로그인 시각 T0로 탈퇴한다
        withdraw.withdraw(account.getPublicId(), null, T0);

        // 확인: 탈퇴돼야 한다
        assertThat(account.getStatus()).isEqualTo(AccountStatus.WITHDRAWN);
        // 확인: 소셜 연결을 지웠어야 한다
        verify(socialIdentities).deleteByAccountId(account.getId());
        // 확인: 리프레시 토큰을 모두 지웠어야 한다
        verify(refreshTokens).revokeAll(account.getPublicId());
    }

    // [상황] 같은 소셜 고객이 로그인한 지 10분이 지났거나 로그인 시각을 모르는 상태로 탈퇴한다.
    // [기대] 403 REAUTH_REQUIRED(다시 로그인하세요), 탈퇴되지 않는다(남이 켜 둔 화면으로 탈퇴 방지).
    //        ※ 응답 코드: 403 = 권한 없음(누구인지는 알지만 허락되지 않은 일)
    @Test
    @DisplayName("비밀번호 없는 탈퇴는 로그인한 지 10분이 지났거나 로그인 시각을 모르면 403 REAUTH_REQUIRED이고 탈퇴되지 않는다")
    void passwordlessWithdrawNeedsRecentLogin() {
        // 준비: 소셜 가입 계정을 만든다
        Account account = socialOnlyAccount("old@trace.test");
        // 준비: 로그인 뒤 11분이 지나게 한다
        clock.advance(Duration.ofMinutes(11));

        // 실행+확인: 비밀번호 없이 탈퇴하면
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                // REAUTH_REQUIRED(403, 다시 로그인 필요)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.REAUTH_REQUIRED);
        // 실행+확인: 로그인 시각을 모르는(null) 채 빈 비밀번호로 탈퇴해도
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "", null))
                // REAUTH_REQUIRED여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.REAUTH_REQUIRED);
        // 확인: 탈퇴되지 않고 ACTIVE 그대로여야 한다
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 비밀번호로 가입한 고객(소셜도 연결됨)이 비밀번호 없이 탈퇴하려 한다.
    // [기대] 401, 탈퇴되지 않는다.
    //        ※ 응답 코드: 401 = 로그인 필요(토큰이 없거나 만료·위조됨)
    @Test
    @DisplayName("비밀번호를 정한 계정은 소셜이 자동 연결돼 있어도 비밀번호를 빼면 401이고 탈퇴되지 않는다")
    void passwordAccountNeedsPassword() {
        // 준비: 비밀번호로 가입한다
        signup.signup("p@trace.test", "pass-1234", "비번", true);
        // 준비: 인증한다
        signup.verify("p@trace.test", "123456");
        // 그 계정을 꺼낸다
        Account account = accountRows.get(0);
        // 준비: 그 계정에 구글 연결이 붙어 있다고 답하게 한다
        given(socialIdentities.findByAccountId(account.getId())).willReturn(java.util.List.of(
                new com.gakdo.trace.auth.social.domain.SocialIdentity(account.getId(),
                        com.gakdo.trace.auth.social.domain.SocialProvider.GOOGLE, "g-1", "p@trace.test", T0)));

        // 실행+확인: 비밀번호 없이 탈퇴하면
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                // INVALID_CREDENTIALS(401)여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        // 실행+확인: 빈 비밀번호로 탈퇴해도
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), "", T0))
                // INVALID_CREDENTIALS여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
        // 확인: 탈퇴되지 않아야 한다
        assertThat(account.getStatus()).isEqualTo(AccountStatus.ACTIVE);
    }

    // [상황] 소셜 가입 고객이 비밀번호를 재설정해 비밀번호를 갖게 된다.
    // [기대] 그다음부터는 탈퇴에 비밀번호가 필요하다.
    @Test
    @DisplayName("소셜 가입 계정도 비밀번호를 재설정하면 그다음부터는 탈퇴에 비밀번호가 필요하다")
    void resetPasswordMakesPasswordSet() {
        // 준비: 소셜 가입 계정을 만든다
        Account account = socialOnlyAccount("r@trace.test");
        // (도구) isFalse() = 값이 false여야 통과
        // 준비: (먼저 확인) 처음엔 "비밀번호 정한 적 없음"이어야 한다
        assertThat(account.isPasswordSet()).isFalse();

        // 실행: 비밀번호를 재설정한다
        account.changePassword("new-pass-1234", T0);

        // (도구) isTrue() = 값이 true여야 통과
        // 확인: "비밀번호 정함"으로 바뀌어야 한다
        assertThat(account.isPasswordSet()).isTrue();
        // 실행+확인: 이제 비밀번호 없이 탈퇴하면
        assertThatThrownBy(() -> withdraw.withdraw(account.getPublicId(), null, T0))
                // INVALID_CREDENTIALS여야 한다
                .extracting(e -> ((AuthException) e).code()).isEqualTo(ErrorCode.INVALID_CREDENTIALS);
    }

    /** 소셜 가입처럼 아무도 모르는 비밀번호를 가진 ACTIVE 계정. */
    // 도우미: 소셜 가입처럼 아무도 모르는 비밀번호를 가진 사용 가능 계정을 만든다.
    private Account socialOnlyAccount(String email) {
        // 그 이메일로 가입하고
        signup.signup(email, "pass-1234", "소셜", true);
        // 인증해서 사용 가능 계정으로 만든 뒤
        signup.verify(email, "123456");
        // 그 계정을 꺼내
        Account account = accountRows.get(0);
        // 비밀번호를 아무도 모르는 값으로 바꾼다(소셜 가입과 같은 상태)
        account.replaceWithUnusablePassword("unusable", T0);
        // 그 계정을 돌려준다
        return account;
    }

    // 테스트 도구: 메모리 목록에서 이메일로 계정을 찾는다
    private Optional<Account> find(String email) {
        // 이메일이 같은 첫 계정을 돌려준다(없으면 빈 값)
        return accountRows.stream().filter(a -> email != null && email.equals(a.getEmail())).findFirst();
    }

    // 테스트 도구: 계정의 감춰진 번호(id) 칸을 직접 채운다(DB가 붙이는 번호 흉내)
    private static void setId(Account account, long id) {
        try {
            // (도구) 리플렉션 = 감춰진(private) 칸을 테스트에서 직접 바꾸는 방법
            // 번호 칸을 찾는다
            var field = Account.class.getDeclaredField("id");
            // 바꿀 수 있게 연다
            field.setAccessible(true);
            // 번호를 넣는다
            field.set(account, id);
        } catch (ReflectiveOperationException e) {
            // 실패하면 시험을 멈추게 예외로 바꿔 던진다
            throw new IllegalStateException(e);
        }
    }

    /** 만료를 시험하려고 시간을 앞으로 돌릴 수 있는 시계. */
    // 도우미: 시간을 앞으로 돌릴 수 있는 가짜 시계(10분 만료 등을 시험).
    static final class MutableClock extends Clock {
        // 가짜 시계가 가리키는 지금 시각
        private Instant now;

        MutableClock(Instant now) {
            // 처음 시각을 정한다
            this.now = now;
        }

        // 시간을 d만큼 앞으로 돌린다
        void advance(Duration d) {
            // 지금 시각에 d를 더한다
            now = now.plus(d);
        }

        @Override
        public ZoneId getZone() {
            // 시간대는 UTC
            return ZoneOffset.UTC;
        }

        @Override
        public Clock withZone(ZoneId zone) {
            // 시간대를 바꿔도 같은 시계를 쓴다
            return this;
        }

        @Override
        public Instant instant() {
            // 지금 시각을 돌려준다
            return now;
        }
    }
}
