package com.gakdo.trace.auth.capture.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.capture_link. 수령 촬영 QR의 1회용 토큰. 원문은 QR에만 있고 여기에는 SHA-256만 둔다. */
@Entity
@Table(name = "capture_link", schema = "auth")
public class CaptureLink {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "checkpoint_id")
    private String checkpointId;

    @Column(name = "rental_id")
    private String rentalId;

    @Column(name = "token_hash", columnDefinition = "char(64)")
    private String tokenHash;

    @Column(name = "expires_at")
    private Instant expiresAt;

    @Column(name = "used_at")
    private Instant usedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected CaptureLink() {
    }

    public CaptureLink(String rentalId, String checkpointId, String tokenHash, Instant expiresAt,
                       Instant now) {
        this.rentalId = rentalId;
        this.checkpointId = checkpointId;
        this.tokenHash = tokenHash;
        this.expiresAt = expiresAt;
        this.createdAt = now;
        this.updatedAt = now;
    }

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

    public String getTokenHash() {
        return tokenHash;
    }
}
