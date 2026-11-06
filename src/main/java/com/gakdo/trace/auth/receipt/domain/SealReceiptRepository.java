package com.gakdo.trace.auth.receipt.domain;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import jakarta.persistence.LockModeType;

public interface SealReceiptRepository extends JpaRepository<SealReceipt, Long> {

    boolean existsByCheckpointId(String checkpointId);

    /** 아직 안 보낸 영수증. 이벤트와 렌탈 연결이 동시에 와도 한 번만 보내도록 행을 잠근다. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    List<SealReceipt> findByRentalIdAndSentAtIsNullOrderBySealedAtAsc(String rentalId);
}
