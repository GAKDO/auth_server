package com.gakdo.trace.auth.capture.domain;

import java.time.Instant;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface CaptureLinkRepository extends JpaRepository<CaptureLink, Long> {

    Optional<CaptureLink> findByTokenHash(String tokenHash);

    @Modifying(clearAutomatically = true)
    @Query("update CaptureLink c set c.usedAt = :now, c.updatedAt = :now where c.id = :id and c.usedAt is null")
    int markUsed(@Param("id") Long id, @Param("now") Instant now);
}
