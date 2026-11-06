package com.gakdo.trace.auth.account.application;

import java.time.Clock;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/** 고객 탈퇴(FR-USR-04): 비밀번호 확인 → 개인정보 삭제·WITHDRAWN → 리프레시 토큰 전부 폐기. 렌탈 기록은 남는다. */
@Service
public class WithdrawService {

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenStore refreshTokens;
    private final Clock clock;

    public WithdrawService(AccountRepository accounts, PasswordEncoder passwordEncoder,
                           RefreshTokenStore refreshTokens, Clock clock) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokens = refreshTokens;
        this.clock = clock;
    }

    @Transactional
    public void withdraw(String accountPublicId, String password) {
        Account account = accounts.findByPublicId(accountPublicId)
                .filter(a -> a.getRole() == AccountRole.CUSTOMER && a.getStatus() != AccountStatus.WITHDRAWN)
                .orElseThrow(() -> new AuthException(ErrorCode.UNAUTHENTICATED));
        if (!passwordEncoder.matches(password, account.getPasswordHash())) {
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }
        account.withdraw(clock.instant());
        refreshTokens.revokeAll(accountPublicId);
    }
}
