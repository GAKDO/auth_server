package com.gakdo.trace.auth.receipt;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.amqp.AmqpRejectAndDontRequeueException;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.receipt.application.ReceiptService;
import com.gakdo.trace.auth.receipt.application.SealedRecord;
import com.gakdo.trace.auth.receipt.infra.RecordSealedListener;

class RecordSealedListenerTest {

    private static final String EXAMPLE = """
            {"schemaVersion":"1.0","eventId":"XSa6pteaU6XHloZZ3zVXI","occurredAt":"2026-11-09T14:10:31+09:00",
             "rentalId":"Ws0HLv6QRbDILPWOcz5I2","checkpointId":"h40b9AN9xMQhXRHrOyJWB","seq":2,
             "checkpointType":"RCV","grade":"B",
             "payloadHash":"b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
             "prevHash":"2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae",
             "signedAt":"2026-11-09T14:10:31+09:00"}
            """;

    private final RecordSealedListener listener = new RecordSealedListener(mock(ReceiptService.class),
            new ObjectMapper());

    @Test
    @DisplayName("contracts 예시 이벤트에서 렌탈·시점·종류·지문·봉인 시각을 읽는다")
    void readsContractExample() {
        SealedRecord sealed = listener.parse(EXAMPLE);
        assertThat(sealed.rentalId()).isEqualTo("Ws0HLv6QRbDILPWOcz5I2");
        assertThat(sealed.checkpointId()).isEqualTo("h40b9AN9xMQhXRHrOyJWB");
        assertThat(sealed.checkpointType()).isEqualTo("RCV");
        assertThat(sealed.payloadHash()).startsWith("b94d27b9");
        assertThat(sealed.sealedAt()).isEqualTo(Instant.parse("2026-11-09T05:10:31Z"));
    }

    @Test
    @DisplayName("형식이 깨진 이벤트는 다시 시도하지 않고 DLQ로 보낸다")
    void rejectsBrokenEvents() {
        assertThatThrownBy(() -> listener.parse("not json")).isInstanceOf(AmqpRejectAndDontRequeueException.class);
        assertThatThrownBy(() -> listener.parse(EXAMPLE.replace("\"RCV\"", "\"XXX\"")))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        assertThatThrownBy(() -> listener.parse(EXAMPLE.replace("b94d27b9", "B94D27B9")))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        assertThatThrownBy(() -> listener.parse(EXAMPLE.replace("Ws0HLv6QRbDILPWOcz5I2", "short")))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
    }
}
