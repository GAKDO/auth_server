package com.gakdo.trace.auth.common.domain;

/** 도메인 오류. GlobalExceptionHandler가 Problem Details(code 포함)로 바꾼다. */
public class AuthException extends RuntimeException {

    private final ErrorCode code;

    public AuthException(ErrorCode code) {
        super(code.title());
        this.code = code;
    }

    public ErrorCode code() {
        return code;
    }
}
