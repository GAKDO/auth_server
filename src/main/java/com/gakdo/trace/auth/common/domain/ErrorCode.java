package com.gakdo.trace.auth.common.domain;

import org.springframework.http.HttpStatus;

/** contracts codes.yaml error_code 중 auth-server가 내는 값. 제목은 화면이 아닌 로그·디버그용 기본 문장이다. */
public enum ErrorCode {
    VALIDATION_FAILED(HttpStatus.BAD_REQUEST, "요청 형식이 맞지 않습니다"),
    UNAUTHENTICATED(HttpStatus.UNAUTHORIZED, "로그인이 필요합니다"),
    FORBIDDEN(HttpStatus.FORBIDDEN, "권한이 없습니다"),
    INTERNAL_ERROR(HttpStatus.INTERNAL_SERVER_ERROR, "잠시 후 다시 시도해 주세요"),
    INVALID_CREDENTIALS(HttpStatus.UNAUTHORIZED, "이메일 또는 비밀번호가 맞지 않습니다"),
    EMAIL_NOT_VERIFIED(HttpStatus.FORBIDDEN, "이메일 인증을 먼저 해 주세요"),
    REFRESH_INVALID(HttpStatus.UNAUTHORIZED, "다시 로그인해 주세요"),
    CAPTURE_LINK_INVALID(HttpStatus.GONE, "만료되었거나 이미 사용한 QR입니다"),
    RENTAL_LINKED_TO_OTHER(HttpStatus.CONFLICT, "다른 계정에 연결된 렌탈입니다"),
    CLIENT_CREDENTIALS_INVALID(HttpStatus.UNAUTHORIZED, "부스 자격이 맞지 않습니다"),
    PAIRING_CODE_INVALID(HttpStatus.BAD_REQUEST, "페어링 코드가 맞지 않습니다"),
    PAIRING_CODE_EXPIRED(HttpStatus.GONE, "페어링 코드가 만료되었습니다"),
    RATE_LIMITED(HttpStatus.TOO_MANY_REQUESTS, "잠시 후 다시 시도해 주세요"),
    CONSENT_REQUIRED(HttpStatus.BAD_REQUEST, "개인정보 수집에 동의해 주세요"),
    EMAIL_ALREADY_EXISTS(HttpStatus.CONFLICT, "이미 가입된 이메일입니다"),
    CODE_INVALID(HttpStatus.BAD_REQUEST, "인증 코드가 맞지 않습니다"),
    CODE_EXPIRED(HttpStatus.GONE, "인증 코드가 만료되었습니다"),
    RESEND_TOO_SOON(HttpStatus.TOO_MANY_REQUESTS, "잠시 후 다시 요청해 주세요"),
    REAUTH_REQUIRED(HttpStatus.FORBIDDEN, "다시 로그인한 뒤 해 주세요");

    private final HttpStatus status;
    private final String title;

    ErrorCode(HttpStatus status, String title) {
        this.status = status;
        this.title = title;
    }

    public HttpStatus status() {
        return status;
    }

    public String title() {
        return title;
    }
}
