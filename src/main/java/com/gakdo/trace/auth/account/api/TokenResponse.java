package com.gakdo.trace.auth.account.api;

import com.gakdo.trace.auth.account.application.LoginResult;

/** contracts TokenResponse. */
public record TokenResponse(String accessToken, String tokenType, long expiresIn, String role) {

    static TokenResponse from(LoginResult result) {
        return new TokenResponse(result.accessToken().value(), "Bearer", result.accessToken().expiresInSeconds(),
                result.role().name());
    }
}
