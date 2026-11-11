package com.gakdo.trace.auth.receipt.application;

import java.time.Instant;

/** trace.record.sealed에서 영수증에 쓰는 값만 뽑은 것. */
public record SealedRecord(String rentalId, String checkpointId, String checkpointType, String payloadHash,
                           Instant sealedAt) {
}
