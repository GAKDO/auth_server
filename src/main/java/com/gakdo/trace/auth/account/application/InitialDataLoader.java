package com.gakdo.trace.auth.account.application;

import java.time.Clock;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.booth.domain.ClientCredential;
import com.gakdo.trace.auth.booth.domain.ClientCredentialRepository;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.config.AuthProperties;

/**
 * 관리자 계정·부스 자격·시연용 고객 계정을 환경 변수(trace-secrets)로 만든다. 이미 있으면 건드리지 않는다.
 * 관리자는 가입 화면이 아니라 초기 데이터로 만든다(설계서 "회원가입 규칙").
 * 시연용 고객은 decisions.md 11/2 "회원 화면은 C, 데모 계정은 A"에 따라 이메일 인증을 마친 상태로 만든다.
 * 비밀번호는 해시만 저장하고 로그에 남기지 않는다.
 */
@Component
public class InitialDataLoader implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(InitialDataLoader.class);
    private static final int BOOTH_ID_MAX = 32;

    private final AccountRepository accounts;
    private final ClientCredentialRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final AuthProperties properties;
    private final Clock clock;

    public InitialDataLoader(AccountRepository accounts, ClientCredentialRepository clients,
                             PasswordEncoder passwordEncoder, AuthProperties properties, Clock clock) {
        this.accounts = accounts;
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.properties = properties;
        this.clock = clock;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        seedAdmin();
        seedBooth();
        seedDemoCustomer();
    }

    void seedAdmin() {
        AuthProperties.InitialAdmin admin = properties.initialAdmin();
        if (admin == null || isBlank(admin.email()) || isBlank(admin.password())) {
            log.warn("ADMIN_EMAIL·ADMIN_PASSWORD가 없어 초기 관리자를 만들지 않습니다");
            return;
        }
        String email = Account.normalizeEmail(admin.email());
        if (accounts.existsByEmail(email)) {
            return;
        }
        accounts.save(Account.admin(NanoId.next(), email, passwordEncoder.encode(admin.password()), "관리자",
                clock.instant()));
        log.info("초기 관리자 계정을 만들었습니다");
    }

    void seedBooth() {
        AuthProperties.InitialBooth booth = properties.initialBooth();
        if (booth == null || isBlank(booth.clientId()) || isBlank(booth.clientSecret())) {
            log.warn("BOOTH_CLIENT_ID·BOOTH_CLIENT_SECRET이 없어 부스 자격을 만들지 않습니다");
            return;
        }
        if (booth.clientId().length() > BOOTH_ID_MAX) {
            throw new IllegalStateException("BOOTH_CLIENT_ID는 32자 이하여야 합니다(boothId로 쓰임)");
        }
        if (clients.findByClientId(booth.clientId()).isPresent()) {
            return;
        }
        clients.save(ClientCredential.booth(booth.clientId(),
                passwordEncoder.encode(booth.clientSecret()), clock.instant()));
        log.info("부스 자격 {}을 만들었습니다", booth.clientId());
    }

    void seedDemoCustomer() {
        AuthProperties.DemoCustomer demo = properties.demoCustomer();
        if (demo == null || isBlank(demo.email()) || isBlank(demo.password())) {
            // 시연용이라 없는 것이 정상인 환경도 있다(경고가 아니라 안내)
            log.info("DEMO_CUSTOMER_EMAIL·DEMO_CUSTOMER_PASSWORD가 없어 시연용 고객 계정을 만들지 않습니다");
            return;
        }
        String email = Account.normalizeEmail(demo.email());
        if (accounts.existsByEmail(email)) {
            // 비밀번호를 덮어쓰지 않는다. 같은 이메일이 관리자여도 그대로 둔다
            return;
        }
        accounts.save(Account.customer(NanoId.next(), email, passwordEncoder.encode(demo.password()), "시연 고객",
                AccountStatus.ACTIVE, clock.instant()));
        log.info("시연용 고객 계정을 만들었습니다");
    }

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
