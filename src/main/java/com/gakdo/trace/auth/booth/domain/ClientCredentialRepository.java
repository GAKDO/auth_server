package com.gakdo.trace.auth.booth.domain;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface ClientCredentialRepository extends JpaRepository<ClientCredential, Long> {

    Optional<ClientCredential> findByClientId(String clientId);
}
