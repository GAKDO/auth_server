package com.gakdo.trace.auth.social.application;

import java.time.Clock;
import java.time.Instant;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.application.LoginResult;
import com.gakdo.trace.auth.account.application.LoginService;
import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.social.domain.SocialIdentity;
import com.gakdo.trace.auth.social.domain.SocialIdentityRepository;

/**
 * 소셜 로그인: 제공자 사용자 번호로 연결된 계정을 찾고, 없으면 인증된 이메일로 기존 계정에 연결하거나 새 고객 계정을 만든다.
 * 이메일은 반드시 받는다(인증된 이메일이 없으면 가입시키지 않음).
 */
@Service
public class SocialLoginService {

    private static final int NAME_MAX = 64;

    private final SocialIdentityRepository identities;
    private final AccountRepository accounts;
    private final LoginService loginService;
    private final PasswordEncoder passwordEncoder;
    private final SecureTokens secureTokens;
    private final Clock clock;

    public SocialLoginService(SocialIdentityRepository identities, AccountRepository accounts,
                              LoginService loginService, PasswordEncoder passwordEncoder, SecureTokens secureTokens,
                              Clock clock) {
        this.identities = identities;
        this.accounts = accounts;
        this.loginService = loginService;
        this.passwordEncoder = passwordEncoder;
        this.secureTokens = secureTokens;
        this.clock = clock;
    }

    @Transactional
    public LoginResult login(SocialProfile profile) {
        Instant now = clock.instant();
        Account linked = identities.findByProviderAndSubject(profile.provider(), profile.subject())
                .flatMap(identity -> accounts.findById(identity.getAccountId()).map(a -> unlinkIfWithdrawn(identity, a)))
                .orElse(null);
        if (linked != null) {
            requireCustomer(linked);
            return loginService.issueFor(linked);
        }
        String email = Account.normalizeEmail(profile.email());
        if (email == null || email.isBlank()) {
            throw new SocialLoginException(SocialLoginError.EMAIL_REQUIRED, "인증된 이메일을 받지 못함");
        }
        Account account = accounts.findByEmail(email).orElseGet(() -> createCustomer(profile, email, now));
        requireCustomer(account);
        if (account.getStatus() == AccountStatus.PENDING) {
            // 메일 인증 전 계정의 비밀번호는 이메일 주인이 정했다고 볼 수 없다(남이 먼저 가입했을 수 있음).
            // 아무도 모르는 난수로 바꿔 그 비밀번호로는 로그인하지 못하게 한다. 비밀번호 재설정으로 새로 정할 수 있다.
            account.replaceWithUnusablePassword(unusablePassword(), now);
        }
        // 제공자가 인증한 이메일이므로 메일 인증 전(PENDING) 계정도 인증을 끝낸다
        account.verifyEmail(now);
        // 같은 제공자의 다른 사용자 번호가 이미 붙어 있으면(제공자 계정을 바꿈) 새 번호로 바꾼다
        identities.findByAccountIdAndProvider(account.getId(), profile.provider()).ifPresent(identities::delete);
        identities.flush();
        identities.save(new SocialIdentity(account.getId(), profile.provider(), profile.subject(), email, now));
        return loginService.issueFor(account);
    }

    /** 관리자 계정은 비밀번호 로그인만 쓴다. 소셜 로그인으로 관리자 권한이 열리지 않게 고객 계정만 받는다. */
    private static void requireCustomer(Account account) {
        if (account.getRole() != AccountRole.CUSTOMER) {
            throw new SocialLoginException(SocialLoginError.PROVIDER_ERROR, "소셜 로그인은 고객 계정만 쓸 수 있음");
        }
    }

    private String unusablePassword() {
        return passwordEncoder.encode(secureTokens.opaqueToken());
    }

    /** 탈퇴한 계정에 붙은 연결은 지우고 새 계정으로 가입하게 한다. */
    private Account unlinkIfWithdrawn(SocialIdentity identity, Account account) {
        if (account.getStatus() == AccountStatus.WITHDRAWN) {
            identities.delete(identity);
            identities.flush();
            return null;
        }
        return account;
    }

    /**
     * 소셜 가입 고객. 비밀번호 로그인은 쓰지 않으므로 아무도 모르는 난수의 해시를 넣는다(비밀번호 재설정으로 나중에 정할 수 있다).
     * 로그인 화면의 "처음 로그인하면 개인정보 수집·이용에 동의" 안내를 동의로 보고 지금 시각을 남긴다.
     */
    private Account createCustomer(SocialProfile profile, String email, Instant now) {
        String unusable = unusablePassword();
        Account account = Account.customer(NanoId.next(), email, unusable, displayName(profile, email),
                AccountStatus.ACTIVE, now);
        account.replaceWithUnusablePassword(unusable, now);
        return accounts.saveAndFlush(account);
    }

    static String displayName(SocialProfile profile, String email) {
        String name = profile.name() == null ? "" : profile.name().trim();
        if (name.isEmpty()) {
            int at = email.indexOf('@');
            // '@'가 맨 앞(0)이면 앞부분이 비므로 주소 전체를 이름으로 쓴다
            name = email.substring(0, at > 0 ? at : email.length());
        }
        name = name.replaceAll("\\p{Cntrl}", "");
        return name.length() > NAME_MAX ? name.substring(0, NAME_MAX) : name;
    }
}
