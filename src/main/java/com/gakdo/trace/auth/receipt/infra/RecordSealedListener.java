package com.gakdo.trace.auth.receipt.infra;

import java.nio.charset.StandardCharsets;
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Set;
import java.util.regex.Pattern;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.amqp.AmqpRejectAndDontRequeueException;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.receipt.application.ReceiptService;
import com.gakdo.trace.auth.receipt.application.SealedRecord;

/**
 * trace.record.sealed에서 봉투(rentalId·checkpointId)와 checkpointType·payloadHash·signedAt만 읽는다(너그러운 소비자).
 * 형식이 깨진 메시지는 재시도해도 소용없어 바로 DLQ로 보낸다.
 */
@Component
public class RecordSealedListener {

    private static final Logger log = LoggerFactory.getLogger(RecordSealedListener.class);
    private static final Pattern PUBLIC_ID = Pattern.compile("^[A-Za-z0-9_-]{21}$");
    private static final Pattern SHA256 = Pattern.compile("^[0-9a-f]{64}$");
    private static final Set<String> TYPES = Set.of("OUT", "RCV", "RET");

    private final ReceiptService receipts;
    private final ObjectMapper objectMapper;

    public RecordSealedListener(ReceiptService receipts, ObjectMapper objectMapper) {
        this.receipts = receipts;
        this.objectMapper = objectMapper;
    }

    @RabbitListener(queues = ReceiptAmqpConfig.QUEUE)
    public void onMessage(Message message) {
        handle(new String(message.getBody(), StandardCharsets.UTF_8));
    }

    /** @return 새 영수증을 남겼으면 true */
    public boolean handle(String body) {
        SealedRecord sealed = parse(body);
        boolean created = receipts.recordSealed(sealed);
        log.info("봉인 이벤트 checkpointId={} type={}{}", sealed.checkpointId(), sealed.checkpointType(),
                created ? "" : " (이미 받음)");
        return created;
    }

    public SealedRecord parse(String body) {
        JsonNode event;
        try {
            event = objectMapper.readTree(body);
        } catch (JsonProcessingException e) {
            throw reject("JSON이 아닙니다");
        }
        String rentalId = text(event, "rentalId", PUBLIC_ID);
        String checkpointId = text(event, "checkpointId", PUBLIC_ID);
        String type = event.path("checkpointType").asText("");
        if (!TYPES.contains(type)) {
            throw reject("checkpointType이 OUT·RCV·RET가 아닙니다");
        }
        String payloadHash = text(event, "payloadHash", SHA256);
        try {
            OffsetDateTime signedAt = OffsetDateTime.parse(event.path("signedAt").asText(""));
            return new SealedRecord(rentalId, checkpointId, type, payloadHash, signedAt.toInstant());
        } catch (DateTimeParseException e) {
            throw reject("signedAt 형식이 틀립니다");
        }
    }

    private static String text(JsonNode event, String field, Pattern pattern) {
        String value = event.path(field).asText("");
        if (!pattern.matcher(value).matches()) {
            throw reject(field + " 형식이 틀립니다");
        }
        return value;
    }

    private static AmqpRejectAndDontRequeueException reject(String reason) {
        log.error("봉인 이벤트를 DLQ로 보냅니다: {}", reason);
        return new AmqpRejectAndDontRequeueException(reason);
    }
}
