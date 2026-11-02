package com.gakdo.trace.auth.account.domain;

import java.time.Instant;
import java.util.Locale;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.account. 관리자와 고객을 role로 나눈 한 테이블(설계서 "회원가입 규칙"). */
@Entity
@Table(name = "account", schema = "auth")
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "public_id")
    private String publicId;

    private String email;

    @Column(name = "password_hash")
    private String passwordHash;

    private String name;

    @Enumerated(EnumType.STRING)
    private AccountRole role;

    @Enumerated(EnumType.STRING)
    private AccountStatus status;

    @Column(name = "email_verified_at")
    private Instant emailVerifiedAt;

    @Column(name = "privacy_agreed_at")
    private Instant privacyAgreedAt;

    @Column(name = "withdrawn_at")
    private Instant withdrawnAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected Account() {
    }

    /** 초기 데이터 관리자. 가입 화면을 거치지 않으므로 바로 ACTIVE다. */
    public static Account admin(String publicId, String email, String passwordHash, String name, Instant now) {
        Account account = new Account();
        account.publicId = publicId;
        account.email = normalizeEmail(email);
        account.passwordHash = passwordHash;
        account.name = name;
        account.role = AccountRole.ADMIN;
        account.status = AccountStatus.ACTIVE;
        account.emailVerifiedAt = now;
        account.createdAt = now;
        account.updatedAt = now;
        return account;
    }

    /** 고객 계정(AU2 가입이 쓰고, 지금은 테스트 데이터가 쓴다). */
    public static Account customer(String publicId, String email, String passwordHash, String name, AccountStatus status,
                                   Instant now) {
        Account account = new Account();
        account.publicId = publicId;
        account.email = normalizeEmail(email);
        account.passwordHash = passwordHash;
        account.name = name;
        account.role = AccountRole.CUSTOMER;
        account.status = status;
        account.privacyAgreedAt = now;
        account.emailVerifiedAt = status == AccountStatus.ACTIVE ? now : null;
        account.createdAt = now;
        account.updatedAt = now;
        return account;
    }

    public static String normalizeEmail(String email) {
        return email == null ? null : email.trim().toLowerCase(Locale.ROOT);
    }

    public Long getId() {
        return id;
    }

    public String getPublicId() {
        return publicId;
    }

    public String getEmail() {
        return email;
    }

    public String getPasswordHash() {
        return passwordHash;
    }

    public String getName() {
        return name;
    }

    public AccountRole getRole() {
        return role;
    }

    public AccountStatus getStatus() {
        return status;
    }
}
