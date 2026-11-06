package com.gakdo.trace.auth.account.application;

import com.gakdo.trace.auth.account.domain.AccountStatus;

public record SignupResult(String accountId, AccountStatus status) {
}
