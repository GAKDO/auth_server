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
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름. @SuppressWarnings = 컴파일 경고를 숨긴다
    @Test
    @DisplayName("영수증 메일에 시점 종류, 한국 시간 봉인 시각, 검증 페이지와 같은 지문, 내 렌탈 주소가 들어간다")
    @SuppressWarnings("unchecked")
    void messageCarriesFingerprint() {
        // 준비: 사이트 주소를 https://gakdo.site/로 둔 인증 설정을 만든다(메일 속 내 렌탈 주소에 쓰임)
        AuthProperties auth = new AuthProperties("trace", null, false, "trace:", "https://gakdo.site/",
                null, null, null, null, null, null, null, true, null, null, null);
        // (도구) mock(종류) = 진짜 대신 아무 일도 하지 않는 가짜 객체를 만든다
        // 준비: 메일 보내는 도구는 가짜로 두고, 보내는 사람 team@trace.test·즉시 실행으로 영수증 메일러를 만든다
        SmtpReceiptMailer mailer = new SmtpReceiptMailer(mock(ObjectProvider.class), "smtp.gmail.com",
                new EmailCodeProperties(Duration.ofMinutes(10), 5, Duration.ofSeconds(60), "team@trace.test"),
                auth, Runnable::run);
        // 준비: 검증 페이지와 같은 지문(64자 해시) 값
        String hash = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9";

        // 실행: 홍길동에게 보낼 출고(OUT) 시점 영수증 메일을 만든다(봉인 시각 UTC 05:10:31)
        SimpleMailMessage message = mailer.message("renter@trace.test", "홍길동",
                new Receipt("Ws0HLv6QRbDILPWOcz5I2", "OUT", hash, Instant.parse("2026-11-09T05:10:31Z")));

        // (도구) assertThat(값).검사() = "값이 이래야 한다"를 확인하는 AssertJ 도구. containsExactly(...) = 정확히 그것만 들어 있어야 통과
        // 확인: 받는 사람이 렌탈 고객 한 명이어야 한다
        assertThat(message.getTo()).containsExactly("renter@trace.test");
        // (도구) isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 보내는 사람이 설정한 팀 주소여야 한다
        assertThat(message.getFrom()).isEqualTo("team@trace.test");
        // 확인: 제목에 시점 종류(출고)가 한국어로 들어가야 한다
        assertThat(message.getSubject()).isEqualTo("[TRACE] 출고 기록 봉인 영수증");
        // (도구) contains(글자) = 그 글자가 들어 있어야 통과
        // 확인: 본문에
        assertThat(message.getText())
                // 받는 사람 이름이 있어야 하고
                .contains("홍길동님")
                // 검증 페이지와 같은 지문이 있어야 하고
                .contains(hash)
                // 봉인 시각이 한국 시간으로 적혀 있어야 하고
                .contains("2026-11-09 14:10:31 (한국 시간)")
                // 내 렌탈 화면 주소가 있어야 한다
                .contains("https://gakdo.site/my/rentals");
    }

    // [상황] 메일 서버(SMTP) 설정이 비어 있다.
    // [기대] 메일을 보내지 않고 오류도 내지 않는다(메일 때문에 봉인 처리가 멈추지 않게).
    @Test
    @DisplayName("SMTP 설정이 없으면 보내지 않고 예외도 내지 않는다")
    @SuppressWarnings("unchecked")
    void skipsWithoutSmtp() {
        // 준비: 메일 보내는 도구를 꺼내 주는 공급자를 가짜로 만든다
        ObjectProvider<JavaMailSender> senders = mock(ObjectProvider.class);
        // 준비: 메일 보내는 도구도 가짜로 만든다(실제로 보냈는지 나중에 확인하려고)
        JavaMailSender sender = mock(JavaMailSender.class);
        // (도구) when(가짜.메서드()).thenReturn(결과) = "가짜에게 이 질문이 오면 이 결과를 돌려줘"라고 미리 정해 두는 것
        // 준비: 공급자에게 도구를 달라고 하면 가짜 도구를 주게 한다 = 도구는 있는데 SMTP 주소만 빈 상황
        when(senders.getIfAvailable()).thenReturn(sender);
        // 준비: SMTP 주소를 빈 값("")으로 둔 영수증 메일러를 만든다
        SmtpReceiptMailer mailer = new SmtpReceiptMailer(senders, "", new EmailCodeProperties(null, 0, null, null),
                null, Runnable::run);
        // 실행: 반납 영수증 메일 보내기를 부른다(예외가 나면 여기서 테스트가 실패한다)
        mailer.send("renter@trace.test", null, new Receipt("r", "RET", "h", Instant.EPOCH));
        // (도구) verify(가짜, never()).메서드(any(...)) = 그 메서드가 어떤 값으로도 한 번도 불리지 않았는지 확인
        // 확인: SMTP 설정이 없으니 메일을 보내지 않았어야 한다
        verify(sender, never()).send(any(SimpleMailMessage.class));
    }

    // [상황] 시점 종류 코드를 한국어로 바꾼다.
    // [기대] OUT=출고, RCV=수령, RET=반납.
    @Test
    @DisplayName("시점 종류는 출고·수령·반납으로 적는다")
    void labels() {
        // 실행+확인: OUT은 "출고"로 바뀌어야 한다
        assertThat(SmtpReceiptMailer.label("OUT")).isEqualTo("출고");
        // 실행+확인: RCV는 "수령"으로 바뀌어야 한다
        assertThat(SmtpReceiptMailer.label("RCV")).isEqualTo("수령");
        // 실행+확인: RET은 "반납"으로 바뀌어야 한다
        assertThat(SmtpReceiptMailer.label("RET")).isEqualTo("반납");
    }
}
