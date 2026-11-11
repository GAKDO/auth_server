package com.gakdo.trace.auth.common.domain;

/** 429(RATE_LIMITED·RESEND_TOO_SOON). 응답에 Retry-After(초)를 싣는다. */
public class RateLimitedException extends AuthException {

    private final long retryAfterSeconds;

    public RateLimitedException(long retryAfterSeconds) {
        this(ErrorCode.RATE_LIMITED, retryAfterSeconds);
    }

    /** RATE_LIMITED 말고 RESEND_TOO_SOON처럼 다른 429 코드를 낼 때. */
    public RateLimitedException(ErrorCode code, long retryAfterSeconds) {
        super(code);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
