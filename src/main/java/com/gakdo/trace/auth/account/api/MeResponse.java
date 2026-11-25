package com.gakdo.trace.auth.account.api;

import java.util.List;

import com.gakdo.trace.auth.account.application.MeView;

/** contracts MeResponse. */
public record MeResponse(String accountId, String email, String name, String role, String status,
                         List<String> rentalIds, List<String> socialProviders, boolean passwordSet) {

    static MeResponse from(MeView view) {
        return new MeResponse(view.accountId(), view.email(), view.name(), view.role().name(),
                view.status().name(), view.rentalIds(), view.socialProviders(), view.passwordSet());
    }
}
