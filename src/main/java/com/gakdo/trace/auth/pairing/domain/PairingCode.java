package com.gakdo.trace.auth.pairing.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.pairing_code. 6자리 코드의 SHA-256만 둔다. 5분 1회용. rental_id는 V2에서 더함. */
@Entity
@Table(name = "pairing_code", schema = "auth")
public class PairingCode {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "checkpoint_id")
    private String checkpointId;

    @Column(name = "rental_id")
    private String rentalId;

    @Column(name = "code_hash", columnDefinition = "char(64)")
    private String codeHash;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected PairingCode() {
    }

    public PairingCode(String rentalId, String checkpointId, String codeHash, Instant expiresAt, Instant now) {
        this.rentalId = rentalId;
        this.checkpointId = checkpointId;
        this.codeHash = codeHash;
        this.expiresAt = expiresAt;
        this.createdAt = now;
        this.updatedAt = now;
    }

    /** 아직 쓰지 않았고 만료 전이면 교환할 수 있다. */
    public boolean isUsableAt(Instant now) {
        return usedAt == null && now.isBefore(expiresAt);
    }

    public Long getId() {
        return id;
    }

    public String getCheckpointId() {
        return checkpointId;
    }

    public String getRentalId() {
        return rentalId;
    }

    public String getCodeHash() {
        return codeHash;
    }

    public Instant getExpiresAt() {
        return expiresAt;
    }
}
