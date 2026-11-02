package com.gakdo.trace.auth.pairing.domain;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface PairingCodeRepository extends JpaRepository<PairingCode, Long> {

    boolean existsByCodeHashAndUsedAtIsNullAndExpiresAtAfter(String codeHash, Instant now);

    Optional<PairingCode> findFirstByCodeHashOrderByCreatedAtDesc(String codeHash);

    /** 동시에 두 번 교환해도 한 번만 1을 돌려준다. */
    @Modifying(clearAutomatically = true)
    @Query("update PairingCode p set p.usedAt = :now, p.updatedAt = :now where p.id = :id and p.usedAt is null")
    int markUsed(@Param("id") Long id, @Param("now") Instant now);
}
