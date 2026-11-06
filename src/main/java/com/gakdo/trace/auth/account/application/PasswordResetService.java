package com.gakdo.trace.auth.account.application;

import java.time.Clock;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/** 비밀번호 재설정(FR-USR-06). 없는 이메일도 같은 응답, 바꾸면 그 계정의 리프레시 토큰을 모두 지운다. */
@Service
public class PasswordResetService {

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final EmailCodeService emailCodes;
    private final ResendGuard resendGuard;
    private final RefreshTokenStore refreshTokens;
    private final Clock clock;

    public PasswordResetService(AccountRepository accounts, PasswordEncoder passwordEncoder,
                                EmailCodeService emailCodes, ResendGuard resendGuard,
                                RefreshTokenStore refreshTokens, Clock clock) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.emailCodes = emailCodes;
        this.resendGuard = resendGuard;
        this.refreshTokens = refreshTokens;
        this.clock = clock;
    }

    /** ACTIVE 계정이면 재설정 코드를 보낸다. 없거나 60초 안 재요청이면 아무것도 하지 않는다(응답은 늘 202). */
    @Transactional
    public void requestReset(String email) {
        String normalized = Account.normalizeEmail(email);
        if (resendGuard.tryAcquire(EmailTokenPurpose.RESET, normalized) > 0) {
            return;
        }
        accounts.findByEmail(normalized)
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE)
                .ifPresent(a -> emailCodes.issue(a, EmailTokenPurpose.RESET));
    }

    @Transactional(noRollbackFor = CodeInvalidException.class)
    public void reset(String email, String code, String newPassword) {
        Account account = accounts.findByEmail(Account.normalizeEmail(email))
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(ErrorCode.CODE_EXPIRED));
        emailCodes.consume(account, EmailTokenPurpose.RESET, code);
        account.changePassword(passwordEncoder.encode(newPassword), clock.instant());
        refreshTokens.revokeAll(account.getPublicId());
    }
}
