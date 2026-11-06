package com.gakdo.trace.auth.account.api;

import com.gakdo.trace.auth.account.application.SignupResult;
import com.gakdo.trace.auth.account.domain.AccountStatus;

public record SignupResponse(String accountId, AccountStatus status) {

    static SignupResponse from(SignupResult result) {
        return new SignupResponse(result.accountId(), result.status());
    }
}
