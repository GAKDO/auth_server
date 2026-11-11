package com.gakdo.trace.auth.receipt.application;

import java.time.Instant;

/** 봉인 영수증 메일을 보낸다. 실패해도 예외를 던지지 않고 로그만 남긴다(메일 한 통 때문에 이벤트를 다시 받지 않게). */
public interface ReceiptMailer {

    void send(String to, String name, Receipt receipt);

    record Receipt(String rentalId, String checkpointType, String payloadHash, Instant sealedAt) {
    }
}
