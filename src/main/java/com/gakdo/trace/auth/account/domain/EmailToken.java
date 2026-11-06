package com.gakdo.trace.auth.account.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * auth.email_token. 6자리 코드는 SHA-256 해시만 둔다.
 * 쓰였거나(used_at) 만료됐거나 한도만큼 틀리면 더 이상 받지 않는다.
 */
@Entity
@Table(name = "email_token", schema = "auth")
public class EmailToken {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_id")
    private Long accountId;

    @Enumerated(EnumType.STRING)
    private EmailTokenPurpose purpose;

    @Column(name = "code_hash")
    private String codeHash;

    private short attempts;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected EmailToken() {
    }

    public static EmailToken issue(Long accountId, EmailTokenPurpose purpose, String codeHash, Instant expiresAt,
                                   Instant now) {
        EmailToken token = new EmailToken();
        token.accountId = accountId;
        token.purpose = purpose;
        token.codeHash = codeHash;
        token.expiresAt = expiresAt;
        token.createdAt = now;
        token.updatedAt = now;
        return token;
    }

    public boolean usable(Instant now) {
        return usedAt == null && expiresAt.isAfter(now);
    }

    /** 맞으면 쓰인 것으로 표시한다. */
    public void markUsed(Instant now) {
        usedAt = now;
        updatedAt = now;
    }

    /** 틀린 횟수를 올리고 남은 횟수를 돌려준다. 한도에 닿으면 폐기한다(used_at). */
    public int recordFailure(int maxAttempts, Instant now) {
        attempts++;
        updatedAt = now;
        int remaining = Math.max(0, maxAttempts - attempts);
        if (remaining == 0) {
            usedAt = now;
        }
        return remaining;
    }

    public Long getAccountId() {
        return accountId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public int getAttempts() {
        return attempts;
    }

    public Instant getUsedAt() {
        return usedAt;
    }
}
