package com.gakdo.trace.auth.receipt.infra;

import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.Executor;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.MailException;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.config.EmailCodeProperties;
import com.gakdo.trace.auth.receipt.application.ReceiptMailer;

/**
 * 봉인 영수증 메일(팀 Gmail SMTP). 코드 메일과 같은 SMTP 설정·보내는 주소를 쓰고, 요청 스레드 밖에서 보낸다.
 * 로그에는 받는 주소를 남기지 않는다.
 */
@Component
public class SmtpReceiptMailer implements ReceiptMailer {

    private static final Logger log = LoggerFactory.getLogger(SmtpReceiptMailer.class);
    private static final DateTimeFormatter KST = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss")
            .withZone(ZoneId.of("Asia/Seoul"));

    private final ObjectProvider<JavaMailSender> senders;
    private final String host;
    private final EmailCodeProperties mailProperties;
    private final AuthProperties authProperties;
    private final Executor executor;

    public SmtpReceiptMailer(ObjectProvider<JavaMailSender> senders, @Value("${spring.mail.host:}") String host,
                             EmailCodeProperties mailProperties, AuthProperties authProperties,
                             @Qualifier("applicationTaskExecutor") Executor executor) {
        this.senders = senders;
        this.host = host;
        this.mailProperties = mailProperties;
        this.authProperties = authProperties;
        this.executor = executor;
    }

    @Override
    public void send(String to, String name, Receipt receipt) {
        executor.execute(() -> deliver(to, name, receipt));
    }

    void deliver(String to, String name, Receipt receipt) {
        JavaMailSender sender = senders.getIfAvailable();
        if (host == null || host.isBlank() || sender == null) {
            log.warn("SMTP 설정이 없어 봉인 영수증 메일을 보내지 않았습니다 rentalId={}", receipt.rentalId());
            return;
        }
        try {
            sender.send(message(to, name, receipt));
        } catch (MailException e) {
            log.error("봉인 영수증 메일을 보내지 못했습니다 rentalId={}: {}", receipt.rentalId(),
                    e.getClass().getSimpleName());
        }
    }

    SimpleMailMessage message(String to, String name, Receipt receipt) {
        String label = label(receipt.checkpointType());
        SimpleMailMessage message = new SimpleMailMessage();
        if (mailProperties.from() != null && !mailProperties.from().isBlank()) {
            message.setFrom(mailProperties.from());
        }
        message.setTo(to);
        message.setSubject("[TRACE] " + label + " 기록 봉인 영수증");
        String greeting = name == null || name.isBlank() ? "안녕하세요." : name + "님, 안녕하세요.";
        message.setText(greeting + "\n\n"
                + "렌탈 노트북의 " + label + " 상태 기록이 봉인되었습니다. 아래 지문은 봉인된 기록 전체에서 계산한 값입니다.\n\n"
                + "봉인 시각: " + KST.format(receipt.sealedAt()) + " (한국 시간)\n"
                + "기록 지문(SHA-256): " + receipt.payloadHash() + "\n\n"
                + "이 메일은 업체가 고칠 수 없는 고객님의 메일함에 남습니다. 나중에 리포트의 검증 페이지에 보이는 지문이 "
                + "이 값과 같으면 봉인 뒤 기록이 바뀌지 않았다는 뜻입니다.\n\n"
                + "내 렌탈 보기: " + stripSlash(authProperties.webPublicUrl()) + "/my/rentals\n\n"
                + "TRACE (Trusted Rental Asset Condition Evidence)");
        return message;
    }

    static String label(String checkpointType) {
        return switch (checkpointType) {
            case "OUT" -> "출고";
            case "RCV" -> "수령";
            case "RET" -> "반납";
            default -> "점검";
        };
    }

    private static String stripSlash(String url) {
        return url != null && url.endsWith("/") ? url.substring(0, url.length() - 1) : url;
    }
}
