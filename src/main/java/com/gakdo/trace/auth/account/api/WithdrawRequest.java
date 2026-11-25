package com.gakdo.trace.auth.account.api;

/** contracts WithdrawRequest. password는 소셜 로그인이 연결된 계정만 빼도 된다 */
public record WithdrawRequest(String password) {

    @Override
    public String toString() {
        return "WithdrawRequest[가림: password]";
    }
}
