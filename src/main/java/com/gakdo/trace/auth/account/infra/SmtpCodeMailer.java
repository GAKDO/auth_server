package com.gakdo.trace.auth.account.infra;

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

import com.gakdo.trace.auth.account.application.CodeMailer;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.config.EmailCodeProperties;

/**
 * 팀 Gmail SMTP로 코드 메일을 보낸다(Spring Mail). SMTP_HOST가 비어 있으면 보내지 않고 경고만 남긴다.
 * 로그에는 받는 주소·코드를 남기지 않는다(개인정보·비밀).
 * 발송은 요청 스레드 밖(applicationTaskExecutor)에서 한다. 재설정 요청 응답 시간으로 계정 존재를 알 수 없게(CWE-203).
 */
@Component
public class SmtpCodeMailer implements CodeMailer {

    private static final Logger log = LoggerFactory.getLogger(SmtpCodeMailer.class);

    private final ObjectProvider<JavaMailSender> senders;
    private final String host;
    private final EmailCodeProperties properties;
    private final Executor executor;

    public SmtpCodeMailer(ObjectProvider<JavaMailSender> senders, @Value("${spring.mail.host:}") String host,
                          EmailCodeProperties properties,
                          @Qualifier("applicationTaskExecutor") Executor executor) {
        this.senders = senders;
        this.host = host;
        this.properties = properties;
        this.executor = executor;
    }

    @Override
    public void send(String to, EmailTokenPurpose purpose, String code) {
        executor.execute(() -> deliver(to, purpose, code));
    }

    void deliver(String to, EmailTokenPurpose purpose, String code) {
        JavaMailSender sender = senders.getIfAvailable();
        if (host == null || host.isBlank() || sender == null) {
            log.warn("SMTP 설정이 없어 {} 코드 메일을 보내지 않았습니다", purpose);
            return;
        }
        try {
            sender.send(message(to, purpose, code));
        } catch (MailException e) {
            // 코드는 다시 받을 수 있으므로 요청은 실패시키지 않는다
            log.error("{} 코드 메일을 보내지 못했습니다: {}", purpose, e.getClass().getSimpleName());
        }
    }

    SimpleMailMessage message(String to, EmailTokenPurpose purpose, String code) {
        long minutes = properties.ttl().toMinutes();
        SimpleMailMessage message = new SimpleMailMessage();
        if (properties.from() != null && !properties.from().isBlank()) {
            message.setFrom(properties.from());
        }
        message.setTo(to);
        if (purpose == EmailTokenPurpose.VERIFY) {
            message.setSubject("[TRACE] 이메일 인증 코드");
            message.setText("TRACE 가입을 마치려면 아래 6자리 코드를 입력해 주세요.\n\n" + code
                    + "\n\n코드는 " + minutes + "분 뒤 만료됩니다. 직접 가입하지 않았다면 이 메일은 무시해 주세요.");
        } else {
            message.setSubject("[TRACE] 비밀번호 재설정 코드");
            message.setText("비밀번호를 다시 정하려면 아래 6자리 코드를 입력해 주세요.\n\n" + code
                    + "\n\n코드는 " + minutes + "분 뒤 만료됩니다. 요청하지 않았다면 이 메일은 무시해 주세요.");
        }
        return message;
    }
}
