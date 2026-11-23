// 이 파일이 확인하는 것: 봉인 영수증 메일의 내용과, 메일 설정이 없을 때의 동작.

package com.gakdo.trace.auth.receipt.infra;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.time.Duration;
import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.config.EmailCodeProperties;
import com.gakdo.trace.auth.receipt.application.ReceiptMailer.Receipt;

class SmtpReceiptMailerTest {

    // [상황] 출고 시점 봉인 영수증 메일을 만든다(받는 사람 홍길동).
    // [기대] 제목 "[TRACE] 출고 기록 봉인 영수증", 본문에 이름·지문(공개 검증 페이지와 같은 값)·한국 시간 봉인 시각·
    //        내 렌탈 화면 주소가 들어간다. 고객은 이 지문으로 나중에 기록이 바뀌지 않았는지 확인할 수 있다.
    @Test
    @DisplayName("영수증 메일에 시점 종류, 한국 시간 봉인 시각, 검증 페이지와 같은 지문, 내 렌탈 주소가 들어간다")
    @SuppressWarnings("unchecked")
    void messageCarriesFingerprint() {
        AuthProperties auth = new AuthProperties("trace", null, false, "trace:", "https://gakdo.site/",
                null, null, null, null, null, null, null, true, null, null, null);
        SmtpReceiptMailer mailer = new SmtpReceiptMailer(mock(ObjectProvider.class), "smtp.gmail.com",
                new EmailCodeProperties(Duration.ofMinutes(10), 5, Duration.ofSeconds(60), "team@trace.test"),
                auth, Runnable::run);
        String hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        SimpleMailMessage message = mailer.message("renter@trace.test", "홍길동",
                new Receipt("Ws0HLv6QRbDILPWOcz5I2", "OUT", hash, Instant.parse("2026-11-09T05:10:31Z")));

        assertThat(message.getTo()).containsExactly("renter@trace.test");
        assertThat(message.getFrom()).isEqualTo("team@trace.test");
        assertThat(message.getSubject()).isEqualTo("[TRACE] 출고 기록 봉인 영수증");
        assertThat(message.getText())
                .contains("홍길동님")
                .contains(hash)
                .contains("2026-11-09 14:10:31 (한국 시간)")
                .contains("https://gakdo.site/my/rentals");
    }

    // [상황] 메일 서버(SMTP) 설정이 비어 있다.
    // [기대] 메일을 보내지 않고 오류도 내지 않는다(메일 때문에 봉인 처리가 멈추지 않게).
    @Test
    @DisplayName("SMTP 설정이 없으면 보내지 않고 예외도 내지 않는다")
    @SuppressWarnings("unchecked")
    void skipsWithoutSmtp() {
        ObjectProvider<JavaMailSender> senders = mock(ObjectProvider.class);
        JavaMailSender sender = mock(JavaMailSender.class);
        when(senders.getIfAvailable()).thenReturn(sender);
        SmtpReceiptMailer mailer = new SmtpReceiptMailer(senders, "", new EmailCodeProperties(null, 0, null, null),
                null, Runnable::run);
        mailer.send("renter@trace.test", null, new Receipt("r", "RET", "h", Instant.EPOCH));
        verify(sender, never()).send(any(SimpleMailMessage.class));
    }

    // [상황] 시점 종류 코드를 한국어로 바꾼다.
    // [기대] OUT=출고, RCV=수령, RET=반납.
    @Test
    @DisplayName("시점 종류는 출고·수령·반납으로 적는다")
    void labels() {
        assertThat(SmtpReceiptMailer.label("OUT")).isEqualTo("출고");
        assertThat(SmtpReceiptMailer.label("RCV")).isEqualTo("수령");
        assertThat(SmtpReceiptMailer.label("RET")).isEqualTo("반납");
    }
}
