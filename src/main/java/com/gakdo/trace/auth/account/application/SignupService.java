package com.gakdo.trace.auth.account.application;

import java.time.Clock;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.domain.RateLimitedException;
import com.gakdo.trace.auth.common.infra.NanoId;

/** 고객 가입·이메일 인증·코드 재발송(FR-USR-01·05). */
@Service
public class SignupService {

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final EmailCodeService emailCodes;
    private final ResendGuard resendGuard;
    private final Clock clock;

    public SignupService(AccountRepository accounts, PasswordEncoder passwordEncoder, EmailCodeService emailCodes,
                         ResendGuard resendGuard, Clock clock) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.emailCodes = emailCodes;
        this.resendGuard = resendGuard;
        this.clock = clock;
    }

    /** PENDING 계정을 만들고 인증 코드를 메일로 보낸다. 동의가 없으면 400, 이메일이 있으면 409. */
    @Transactional
    public SignupResult signup(String email, String password, String name, boolean privacyAgreed) {
        if (!privacyAgreed) {
            throw new AuthException(ErrorCode.CONSENT_REQUIRED);
        }
        String normalized = Account.normalizeEmail(email);
        if (accounts.existsByEmail(normalized)) {
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
        Account account = Account.customer(NanoId.next(), normalized, passwordEncoder.encode(password), name.trim(),
                AccountStatus.PENDING, clock.instant());
        try {
            accounts.saveAndFlush(account);
        } catch (DataIntegrityViolationException e) {
            // 같은 이메일로 동시에 가입하면 UNIQUE가 하나만 남긴다
            throw new AuthException(ErrorCode.EMAIL_ALREADY_EXISTS);
        }
        // 가입 메일도 재발송 창을 연다(가입 직후 재발송 연타 방지)
        resendGuard.tryAcquire(EmailTokenPurpose.VERIFY, normalized);
        emailCodes.issue(account, EmailTokenPurpose.VERIFY);
        return new SignupResult(account.getPublicId(), account.getStatus());
    }

    /** 코드가 맞으면 ACTIVE. 계정이 없거나 고객이 아니면 코드가 없는 것과 같이 410(가입 여부를 드러내지 않음). */
    @Transactional(noRollbackFor = CodeInvalidException.class)
    public void verify(String email, String code) {
        Account account = accounts.findByEmail(Account.normalizeEmail(email))
                .filter(a -> a.getRole() == AccountRole.CUSTOMER)
                .orElseThrow(() -> new AuthException(ErrorCode.CODE_EXPIRED));
        if (account.getStatus() == AccountStatus.ACTIVE) {
            return; // 이미 인증됨: 같은 요청을 다시 보내도 성공
        }
        emailCodes.consume(account, EmailTokenPurpose.VERIFY, code);
        account.verifyEmail(clock.instant());
    }

    /** 인증 전 계정이면 새 코드를 보낸다. 대상이 없어도 같은 응답(202). 60초 안 다시 부르면 429 RESEND_TOO_SOON. */
    @Transactional
    public void resend(String email) {
        String normalized = Account.normalizeEmail(email);
        long wait = resendGuard.tryAcquire(EmailTokenPurpose.VERIFY, normalized);
        if (wait > 0) {
            throw new RateLimitedException(ErrorCode.RESEND_TOO_SOON, wait);
        }
        accounts.findByEmail(normalized)
                .filter(a -> a.getRole() == AccountRole.CUSTOMER && a.getStatus() == AccountStatus.PENDING)
                .ifPresent(a -> emailCodes.issue(a, EmailTokenPurpose.VERIFY));
    }
}
