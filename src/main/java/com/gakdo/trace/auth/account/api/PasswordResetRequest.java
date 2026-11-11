package com.gakdo.trace.auth.account.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;

public record PasswordResetRequest(@NotBlank @Email @Size(max = 254) String email,
                                   @NotBlank @Pattern(regexp = "^\\d{6}$") String code,
                                   @NotBlank @Size(min = 8, max = 72) String newPassword) {

    @Override
    public String toString() {
        return "PasswordResetRequest[가림: email, code, newPassword]";
    }
}
