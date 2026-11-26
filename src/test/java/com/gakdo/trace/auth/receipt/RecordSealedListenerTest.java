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

    // (도구) mock(종류) = 진짜 대신 아무 일도 하지 않는 가짜 객체를 만든다. 여기서는 메일 보내기(ReceiptService)를 가짜로 둬 이벤트 읽기만 시험한다
    // 시험할 "봉인됨" 이벤트 리스너를 가짜 영수증 서비스와 JSON 읽기 도구로 만든다
    private final RecordSealedListener listener = new RecordSealedListener(mock(ReceiptService.class),
            new ObjectMapper());

    // [상황] 계약 예시 이벤트를 읽는다.
    // [기대] 렌탈·시점·종류(수령)·지문·봉인 시각(한국 시간 14:10:31 = UTC 05:10:31)을 정확히 읽는다.
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("contracts 예시 이벤트에서 렌탈·시점·종류·지문·봉인 시각을 읽는다")
    void readsContractExample() {
        // 실행: 계약 예시 이벤트 글자를 읽어 봉인 기록으로 바꾼다
        SealedRecord sealed = listener.parse(EXAMPLE);
        // (도구) assertThat(값).isEqualTo(기대값) = "값이 기대값과 같아야 한다"를 확인하는 AssertJ 도구
        // 확인: 렌탈 ID를 정확히 읽어야 한다
        assertThat(sealed.rentalId()).isEqualTo("Ws0HLv6QRbDILPWOcz5I2");
        // 확인: 시점 ID를 정확히 읽어야 한다
        assertThat(sealed.checkpointId()).isEqualTo("h40b9AN9xMQhXRHrOyJWB");
        // 확인: 시점 종류가 수령(RCV)이어야 한다
        assertThat(sealed.checkpointType()).isEqualTo("RCV");
        // (도구) startsWith(글자) = 그 글자로 시작해야 통과
        // 확인: 지문(payloadHash)을 읽어야 한다(앞부분으로 확인)
        assertThat(sealed.payloadHash()).startsWith("b94d27b9");
        // 확인: 봉인 시각이 한국 시간 14:10:31 = UTC 05:10:31로 바르게 바뀌어야 한다
        assertThat(sealed.sealedAt()).isEqualTo(Instant.parse("2026-11-09T05:10:31Z"));
    }

    // [상황] JSON이 아니거나, 시점 종류가 XXX거나, 지문이 대문자거나, 렌탈 번호가 너무 짧은 이벤트.
    // [기대] 다시 시도하지 않고 실패 보관함(DLQ)으로 보낸다(큐가 막히지 않게).
    @Test
    @DisplayName("형식이 깨진 이벤트는 다시 시도하지 않고 DLQ로 보낸다")
    void rejectsBrokenEvents() {
        // (도구) assertThatThrownBy(() -> 코드).isInstanceOf(예외) = 그 코드를 돌리면 이 종류의 예외가 나야 통과
        // 실행+확인: JSON이 아닌 글자를 읽으면 "다시 시도하지 말고 버려라(DLQ)" 예외가 나야 한다 = 깨진 메시지로 큐가 막히지 않게
        assertThatThrownBy(() -> listener.parse("not json")).isInstanceOf(AmqpRejectAndDontRequeueException.class);
        // 준비: 시점 종류를 없는 값(XXX)으로 바꾼 이벤트를 만든다
        String badType = EXAMPLE.replace("\"RCV\"", "\"XXX\"");
        // 준비: 지문을 대문자로 바꾼 이벤트를 만든다
        String upperHash = EXAMPLE.replace("b94d27b9", "B94D27B9");
        // 준비: 렌탈 ID를 너무 짧게 바꾼 이벤트를 만든다
        String shortId = EXAMPLE.replace("Ws0HLv6QRbDILPWOcz5I2", "short");
        // 실행+확인: 시점 종류가 틀린 이벤트는
        assertThatThrownBy(() -> listener.parse(badType))
                // DLQ로 보내는 예외가 나야 한다
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        // 실행+확인: 지문이 대문자인 이벤트는
        assertThatThrownBy(() -> listener.parse(upperHash))
                // DLQ로 보내는 예외가 나야 한다
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
        // 실행+확인: 렌탈 ID가 짧은 이벤트는
        assertThatThrownBy(() -> listener.parse(shortId))
                // DLQ로 보내는 예외가 나야 한다
                .isInstanceOf(AmqpRejectAndDontRequeueException.class);
    }
}
