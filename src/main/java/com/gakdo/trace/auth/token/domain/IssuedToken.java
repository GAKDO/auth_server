package com.gakdo.trace.auth.token.domain;

/** 서명한 JWT와 응답 expiresIn(초). */
public record IssuedToken(String value, long expiresInSeconds) {
}
