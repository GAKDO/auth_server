package com.gakdo.trace.auth.account.application;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.social.domain.SocialIdentityRepository;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/**
 * 고객 탈퇴(FR-USR-04): 비밀번호 확인 → 개인정보 삭제·WITHDRAWN → 소셜 연결 삭제 → 리프레시 토큰 전부 폐기. 렌탈 기록은 남는다.
 * 비밀번호를 정한 적 없는 계정(소셜 가입)은 비밀번호 없이 탈퇴할 수 있다(11/12 팀 결정). 다만 토큰 하나만으로
 * 계정을 지우지 못하게 로그인한 지 10분 안(auth_time)인 세션만 받고, 지났으면 REAUTH_REQUIRED로 다시 로그인하게 한다.
 * 비밀번호로 가입한 뒤 소셜이 자동 연결된 계정은 비밀번호를 정했으므로 계속 비밀번호가 필요하다.
 */
@Service
public class WithdrawService {

    /** 비밀번호 없는 탈퇴를 받는 로그인 뒤 시간. */
    public static final Duration RECENT_LOGIN = Duration.ofMinutes(10);

    private final AccountRepository accounts;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenStore refreshTokens;
    private final SocialIdentityRepository socialIdentities;
    private final Clock clock;

    public WithdrawService(AccountRepository accounts, PasswordEncoder passwordEncoder,
                           RefreshTokenStore refreshTokens, SocialIdentityRepository socialIdentities, Clock clock) {
        this.accounts = accounts;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokens = refreshTokens;
        this.socialIdentities = socialIdentities;
        this.clock = clock;
    }

    @Transactional
    public void withdraw(String accountPublicId, String password, Instant authTime) {
        Account account = accounts.findByPublicId(accountPublicId)
                .filter(a -> a.getRole() == AccountRole.CUSTOMER && a.getStatus() != AccountStatus.WITHDRAWN)
                .orElseThrow(() -> new AuthException(ErrorCode.UNAUTHENTICATED));
        Instant now = clock.instant();
        if (password != null && !password.isEmpty()) {
            if (!passwordEncoder.matches(password, account.getPasswordHash())) {
                throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
            }
        } else if (account.isPasswordSet()) {
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        } else if (authTime == null || authTime.isBefore(now.minus(RECENT_LOGIN))) {
            throw new AuthException(ErrorCode.REAUTH_REQUIRED);
        }
        account.withdraw(now);
        socialIdentities.deleteByAccountId(account.getId());
        refreshTokens.revokeAll(accountPublicId);
    }
}
