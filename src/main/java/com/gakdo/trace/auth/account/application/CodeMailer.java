package com.gakdo.trace.auth.account.application;

import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;

/** 인증·재설정 코드 메일을 보낸다. 실패해도 예외를 던지지 않고 로그만 남긴다(코드는 다시 받을 수 있다). */
public interface CodeMailer {

    void send(String to, EmailTokenPurpose purpose, String code);
}
