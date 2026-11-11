package com.gakdo.trace.auth.account.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record EmailOnlyRequest(@NotBlank @Email @Size(max = 254) String email) {

    @Override
    public String toString() {
        return "EmailOnlyRequest[email=***]";
    }
}
