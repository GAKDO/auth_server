package com.gakdo.trace.auth.account.api;

import jakarta.validation.constraints.NotBlank;

public record WithdrawRequest(@NotBlank String password) {

    @Override
    public String toString() {
        return "WithdrawRequest[가림: password]";
    }
}
