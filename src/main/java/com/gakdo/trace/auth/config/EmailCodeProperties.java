package com.gakdo.trace.auth.config;

import java.time.Duration;

import org.springframework.boot.context.properties.ConfigurationProperties;

/** trace.auth.email-code.*: 인증·재설정 코드 수명(10분)·틀린 횟수 한도(5번)·재발송 간격(60초)·보내는 주소. */
@ConfigurationProperties(prefix = "trace.auth.email-code")
public record EmailCodeProperties(Duration ttl, int maxAttempts, Duration resendInterval, String from) {

    public EmailCodeProperties {
        ttl = ttl == null ? Duration.ofMinutes(10) : ttl;
        maxAttempts = maxAttempts <= 0 ? 5 : maxAttempts;
        resendInterval = resendInterval == null ? Duration.ofSeconds(60) : resendInterval;
    }
}
