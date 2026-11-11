package com.gakdo.trace.auth.common.domain;

/** 400 CODE_INVALID. 응답에 남은 시도 횟수(remainingAttempts)를 싣는다. */
public class CodeInvalidException extends AuthException {

    private final int remainingAttempts;

    public CodeInvalidException(int remainingAttempts) {
        super(ErrorCode.CODE_INVALID);
        this.remainingAttempts = remainingAttempts;
    }

    public int remainingAttempts() {
        return remainingAttempts;
    }
}
