package com.gakdo.trace.auth.account.application;

import java.util.List;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.RentalAccess;
import com.gakdo.trace.auth.account.domain.RentalAccessRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.domain.IssuedToken;
import com.gakdo.trace.auth.token.domain.TokenClaims;
import com.gakdo.trace.auth.token.infra.RefreshTokenStore;

/** 로그인·재발급·로그아웃·내 정보(FR-AUTH-01). */
@Service
public class LoginService {

    private final AccountRepository accounts;
    private final RentalAccessRepository rentalAccesses;
    private final PasswordEncoder passwordEncoder;
    private final RefreshTokenStore refreshTokens;
    private final JwtIssuer jwtIssuer;
    private final AuthProperties properties;
    // 없는 이메일에도 BCrypt 비교를 한 번 해서 응답 시간으로 가입 여부가 드러나지 않게 한다
    private final String dummyHash;

    public LoginService(AccountRepository accounts, RentalAccessRepository rentalAccesses,
                        PasswordEncoder passwordEncoder, RefreshTokenStore refreshTokens, JwtIssuer jwtIssuer,
                        AuthProperties properties) {
        this.accounts = accounts;
        this.rentalAccesses = rentalAccesses;
        this.passwordEncoder = passwordEncoder;
        this.refreshTokens = refreshTokens;
        this.jwtIssuer = jwtIssuer;
        this.properties = properties;
        this.dummyHash = passwordEncoder.encode(java.util.UUID.randomUUID().toString());
    }

    @Transactional(readOnly = true)
    public LoginResult login(String email, String password) {
        Account account = accounts.findByEmail(Account.normalizeEmail(email)).orElse(null);
        if (account == null || account.getPasswordHash() == null) {
            passwordEncoder.matches(password, dummyHash);
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }
        if (!passwordEncoder.matches(password, account.getPasswordHash())
                || account.getStatus() == AccountStatus.WITHDRAWN) {
            throw new AuthException(ErrorCode.INVALID_CREDENTIALS);
        }
        // 비밀번호가 맞을 때만 인증 전임을 알려 준다(틀린 비밀번호로 가입 상태를 알아낼 수 없게)
        if (account.getStatus() == AccountStatus.PENDING) {
            throw new AuthException(ErrorCode.EMAIL_NOT_VERIFIED);
        }
        return issueFor(account);
    }

    @Transactional(readOnly = true)
    public LoginResult refresh(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw new AuthException(ErrorCode.REFRESH_INVALID);
        }
        String accountId = refreshTokens.consume(refreshToken)
                .orElseThrow(() -> new AuthException(ErrorCode.REFRESH_INVALID));
        Account account = accounts.findByPublicId(accountId)
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(ErrorCode.REFRESH_INVALID));
        return issueFor(account);
    }

    public void logout(String refreshToken) {
        if (refreshToken != null && !refreshToken.isBlank()) {
            refreshTokens.revoke(refreshToken);
        }
    }

    @Transactional(readOnly = true)
    public MeView me(String accountPublicId) {
        Account account = accounts.findByPublicId(accountPublicId)
                .filter(a -> a.getStatus() != AccountStatus.WITHDRAWN)
                .orElseThrow(() -> new AuthException(ErrorCode.UNAUTHENTICATED));
        return new MeView(account.getPublicId(), account.getEmail(), account.getName(), account.getRole(),
                account.getStatus(), rentalsOf(account));
    }

    /** 이미 확인한 계정에 액세스·리프레시 토큰을 낸다(비밀번호 로그인·소셜 로그인이 같이 쓴다). */
    public LoginResult issueFor(Account account) {
        TokenClaims claims = account.getRole() == AccountRole.ADMIN
                ? TokenClaims.admin(account.getPublicId(), properties.accessTokenTtl())
                : TokenClaims.customer(account.getPublicId(), rentalsOf(account), properties.accessTokenTtl());
        IssuedToken access = jwtIssuer.issue(claims);
        String refresh = refreshTokens.issue(account.getPublicId());
        return new LoginResult(access, refresh, account.getRole());
    }

    private List<String> rentalsOf(Account account) {
        if (account.getRole() != AccountRole.CUSTOMER) {
            return List.of();
        }
        return rentalAccesses.findByAccountIdOrderByLinkedAtAsc(account.getId()).stream()
                .map(RentalAccess::getRentalId)
                .toList();
    }
}
