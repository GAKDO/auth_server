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
import com.gakdo.trace.auth.booth.domain.ClientCredential;
import com.gakdo.trace.auth.booth.domain.ClientCredentialRepository;
import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.config.AuthProperties;

/**
 * 관리자 계정과 부스 자격을 환경 변수(trace-secrets)로 만든다. 이미 있으면 건드리지 않는다.
 * 관리자는 가입 화면이 아니라 초기 데이터로 만든다(설계서 "회원가입 규칙").
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

    private static boolean isBlank(String value) {
        return value == null || value.isBlank();
    }
}
