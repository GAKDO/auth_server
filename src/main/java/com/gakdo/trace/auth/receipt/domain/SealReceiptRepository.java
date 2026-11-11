package com.gakdo.trace.auth.receipt.domain;

import java.time.Instant;
import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface SealReceiptRepository extends JpaRepository<SealReceipt, Long> {

    boolean existsByCheckpointId(String checkpointId);

    /**
     * 같은 시점(checkpoint_id UNIQUE)이 이미 있으면 넣지 않는다. 예외로 되살리면 트랜잭션이 rollback-only가 되므로
     * 충돌은 DB가 처리하게 한다.
     *
     * @return 넣은 행 수(0이면 이미 받은 시점)
     */
    @Modifying
    @Query(value = """
            INSERT INTO auth.seal_receipt (rental_id, checkpoint_id, checkpoint_type, payload_hash, sealed_at,
                                           created_at, updated_at)
            VALUES (:rentalId, :checkpointId, :type, :hash, :sealedAt, :now, :now)
            ON CONFLICT (checkpoint_id) DO NOTHING
            """, nativeQuery = true)
    int insertIfAbsent(@Param("rentalId") String rentalId, @Param("checkpointId") String checkpointId,
                       @Param("type") String type, @Param("hash") String hash,
                       @Param("sealedAt") Instant sealedAt, @Param("now") Instant now);

    /** 아직 안 보낸 영수증. 이벤트와 렌탈 연결이 동시에 와도 한 번만 보내도록 행을 잠근다. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<SealReceipt> findByRentalIdAndSentAtIsNullOrderBySealedAtAsc(String rentalId);
}
