package com.gakdo.trace.auth.account.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record EmailVerifyRequest(@NotBlank @Email @Size(max = 254) String email,
                                 @NotBlank @Pattern(regexp = "^\\d{6}$") String code) {

    @Override
    public String toString() {
        return "EmailVerifyRequest[email=***, code=***]";
    }
}
