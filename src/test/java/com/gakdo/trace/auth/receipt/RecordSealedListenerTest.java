// 이 파일이 확인하는 것: 봉인 영수증 메일(AU3)의 시작점. report-server가 시점을 봉인하면 "봉인됨" 이벤트가 오고,
// auth-server가 그것을 읽어 고객에게 영수증 메일을 보낸다. 여기서는 이벤트 읽기만 확인한다.

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

    // 계약(contracts)에 있는 "봉인됨" 이벤트 예시: 수령(RCV) 시점, 등급 B, 지문(payloadHash).
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

    // [상황] 계약 예시 이벤트를 읽는다.
    // [기대] 렌탈·시점·종류(수령)·지문·봉인 시각(한국 시간 14:10:31 = UTC 05:10:31)을 정확히 읽는다.
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

    // [상황] JSON이 아니거나, 시점 종류가 XXX거나, 지문이 대문자거나, 렌탈 번호가 너무 짧은 이벤트.
    // [기대] 다시 시도하지 않고 실패 보관함(DLQ)으로 보낸다(큐가 막히지 않게).
    @Test
    @DisplayName("형식이 깨진 이벤트는 다시 시도하지 않고 DLQ로 보낸다")
    void rejectsBrokenEvents() {
        assertThatThrownBy(() -> listener.parse("not json")).isInstanceOf(AmqpRejectAndDontRequeueException.class);
        String badType = EXAMPLE.replace("\"RCV\"", "\"XXX\"");
        String upperHash = EXAMPLE.replace("b94d27b9", "B94D27B9");
        String shortId = EXAMPLE.replace("Ws0HLv6QRbDILPWOcz5I2", "short");
        assertThatThrownBy(() -> listener.parse(badType))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        assertThatThrownBy(() -> listener.parse(upperHash))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        assertThatThrownBy(() -> listener.parse(shortId))
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
    }
}
