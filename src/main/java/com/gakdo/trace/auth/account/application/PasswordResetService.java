package com.gakdo.trace.auth.account.application;

import java.time.Clock;
import java.time.Duration;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.account.domain.EmailTokenRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/** 비밀번호 재설정(FR-USR-06). 없는 이메일도 같은 응답, 바꾸면 그 계정의 리프레시 토큰을 모두 지운다. */
@Service
public class PasswordResetService {

    /**
     * 계정 하나에 하루(24시간) 보내는 재설정 코드 수 상한. 코드마다 틀릴 수 있는 횟수(5번)가 새로 시작하므로,
     * 상한이 없으면 60초마다 다시 요청해 하루 7,200번까지 6자리 코드를 맞혀 볼 수 있었다(관리자 계정 포함).
     * 상한 5면 하루 최대 25번이다. 넘으면 다른 경우와 같이 아무것도 하지 않는다(응답은 늘 202).
     */
    static final int MAX_CODES_PER_DAY = 5;
    private static final Duration WINDOW = Duration.ofHours(24);

    private final AccountRepository accounts;
    private final EmailTokenRepository tokens;
    private final PasswordEncoder passwordEncoder;
    private final EmailCodeService emailCodes;
    private final ResendGuard resendGuard;
    private final RefreshTokenStore refreshTokens;
    private final Clock clock;

    public PasswordResetService(AccountRepository accounts, EmailTokenRepository tokens,
                                PasswordEncoder passwordEncoder, EmailCodeService emailCodes, ResendGuard resendGuard,
                                RefreshTokenStore refreshTokens, Clock clock) {
        this.accounts = accounts;
        this.tokens = tokens;
        this.passwordEncoder = passwordEncoder;
        this.emailCodes = emailCodes;
        this.resendGuard = resendGuard;
        this.refreshTokens = refreshTokens;
        this.clock = clock;
    }

    /** ACTIVE 계정이면 재설정 코드를 보낸다. 없거나 60초 안 재요청이거나 하루 상한을 넘으면 아무것도 하지 않는다(응답은 늘 202). */
    @Transactional
    public void requestReset(String email) {
        String normalized = Account.normalizeEmail(email);
        if (resendGuard.tryAcquire(EmailTokenPurpose.RESET, normalized) > 0) {
            return;
        }
        accounts.findByEmail(normalized)
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE)
                .filter(a -> tokens.countByAccountIdAndPurposeAndCreatedAtAfter(
                        a.getId(), EmailTokenPurpose.RESET, clock.instant().minus(WINDOW)) < MAX_CODES_PER_DAY)
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
