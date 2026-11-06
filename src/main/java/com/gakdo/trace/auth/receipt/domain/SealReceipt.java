package com.gakdo.trace.auth.receipt.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/**
 * auth.seal_receipt. 봉인된 시점마다 한 줄(checkpoint_id UNIQUE).
 * 렌탈이 아직 고객에게 연결되지 않았으면 sent_at이 비어 있다가, 연결될 때 보내고 채운다(설계서 "봉인 영수증 메일").
 */
@Entity
@Table(name = "seal_receipt", schema = "auth")
public class SealReceipt {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "rental_id")
    private String rentalId;

    @Column(name = "checkpoint_id")
    private String checkpointId;

    @Column(name = "checkpoint_type")
    private String checkpointType;

    @Column(name = "payload_hash")
    private String payloadHash;

    @Column(name = "sealed_at")
    private Instant sealedAt;

    @Column(name = "sent_at")
    private Instant sentAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected SealReceipt() {
    }

    public SealReceipt(String rentalId, String checkpointId, String checkpointType, String payloadHash,
                       Instant sealedAt, Instant now) {
        this.rentalId = rentalId;
        this.checkpointId = checkpointId;
        this.checkpointType = checkpointType;
        this.payloadHash = payloadHash;
        this.sealedAt = sealedAt;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public void markSent(Instant now) {
        this.sentAt = now;
        this.updatedAt = now;
    }

    public boolean isSent() {
        return sentAt != null;
    }

    public String getRentalId() {
        return rentalId;
    }

    public String getCheckpointId() {
        return checkpointId;
    }

    public String getCheckpointType() {
        return checkpointType;
    }

    public String getPayloadHash() {
        return payloadHash;
    }

    public Instant getSealedAt() {
        return sealedAt;
    }

    public Instant getSentAt() {
        return sentAt;
    }
}
