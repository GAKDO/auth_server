package com.gakdo.trace.auth.booth.domain;

import java.time.Instant;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Table;

/** auth.client_credential. 부스(Jetson)의 client_id·secret(BCrypt). client_id가 곧 boothId다. */
@Entity
@Table(name = "client_credential", schema = "auth")
public class ClientCredential {

    private static final String KIND_BOOTH = "BOOTH";

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "secret_hash")
    private String secretHash;

    private String kind;

    private boolean active;

    @Column(name = "created_at")
    private Instant createdAt;

    @Column(name = "updated_at")
    private Instant updatedAt;

    protected ClientCredential() {
    }

    public static ClientCredential booth(String clientId, String secretHash, Instant now) {
        ClientCredential credential = new ClientCredential();
        credential.clientId = clientId;
        credential.secretHash = secretHash;
        credential.kind = KIND_BOOTH;
        credential.active = true;
        credential.createdAt = now;
        credential.updatedAt = now;
        return credential;
    }

    public String getClientId() {
        return clientId;
    }

    public String getSecretHash() {
        return secretHash;
    }

    public boolean isActive() {
        return active;
    }

    public boolean isBooth() {
        return KIND_BOOTH.equals(kind);
    }
}
