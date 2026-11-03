package com.gakdo.trace.auth.common.domain;

/** 429 RATE_LIMITED. 응답에 Retry-After(초)를 싣는다. */
public class RateLimitedException extends AuthException {

    private final long retryAfterSeconds;

    public RateLimitedException(long retryAfterSeconds) {
        super(ErrorCode.RATE_LIMITED);
        this.retryAfterSeconds = retryAfterSeconds;
    }

    public long retryAfterSeconds() {
        return retryAfterSeconds;
    }
}
