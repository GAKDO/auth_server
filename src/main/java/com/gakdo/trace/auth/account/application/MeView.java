package com.gakdo.trace.auth.account.application;

import java.util.List;

import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.account.domain.AccountStatus;

public record MeView(String accountId, String email, String name, AccountRole role, AccountStatus status,
                     List<String> rentalIds, List<String> socialProviders, boolean passwordSet) {
}
