package com.gakdo.trace.auth.social.application;

/** 소셜 로그인을 끝내지 못함. 컨트롤러가 웹 로그인 화면으로 사유를 실어 돌려보낸다. */
public class SocialLoginException extends RuntimeException {

    private final SocialLoginError error;

    public SocialLoginException(SocialLoginError error, String message) {
        super(message);
        this.error = error;
    }

    public SocialLoginException(SocialLoginError error, String message, Throwable cause) {
        super(message, cause);
        this.error = error;
    }

    public SocialLoginError error() {
        return error;
    }
}
