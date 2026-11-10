package com.gakdo.trace.auth.account.api;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;

/** 동의(privacyAgreed)가 false면 형식 오류가 아니라 400 CONSENT_REQUIRED다(서비스에서 판단). */
public record SignupRequest(@NotBlank @Email @Size(max = 254) String email,
                            @NotBlank @Size(min = 8, max = 72) String password,
                            @NotBlank @Size(max = 64) String name,
                            @NotNull Boolean privacyAgreed) {

    @Override
    public String toString() {
        return "SignupRequest[가림: email, password, name; privacyAgreed " + privacyAgreed + "]";
    }
}
