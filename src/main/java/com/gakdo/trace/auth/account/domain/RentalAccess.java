package com.gakdo.trace.auth.account.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.rental_access. 고객 계정과 렌탈의 연결, 렌탈 하나에 계정 하나(rental_id UNIQUE). */
@Entity
@Table(name = "rental_access", schema = "auth")
public class RentalAccess {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "account_id")
    private Long accountId;

    @Column(name = "rental_id")
    private String rentalId;

    @Column(name = "linked_at")
    private Instant linkedAt;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected RentalAccess() {
    }

    public RentalAccess(Long accountId, String rentalId, Instant now) {
        this.accountId = accountId;
        this.rentalId = rentalId;
        this.linkedAt = now;
        this.createdAt = now;
        this.updatedAt = now;
    }

    public Long getAccountId() {
        return accountId;
    }

    public String getRentalId() {
        return rentalId;
    }
}
