package com.gakdo.trace.auth.social.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.social_identity. 제공자 사용자 번호(subject)와 TRACE 계정의 연결. */
@Entity
@Table(name = "social_identity", schema = "auth")
public class SocialIdentity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_id")
    private Long accountId;

    @Enumerated(EnumType.STRING)
    private SocialProvider provider;

    private String subject;

    private String email;

    @Column(name = "linked_at")
    private Instant linkedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected SocialIdentity() {
    }

    public SocialIdentity(Long accountId, SocialProvider provider, String subject, String email, Instant now) {
        this.accountId = accountId;
        this.provider = provider;
        this.subject = subject;
        this.email = email;
        this.linkedAt = now;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public Long getAccountId() {
        return accountId;
    }

    public SocialProvider getProvider() {
        return provider;
    }

    public String getSubject() {
        return subject;
    }
}
