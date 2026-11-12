package com.gakdo.trace.auth.token.domain;

import java.time.Instant;
import java.util.Objects;

/** 리프레시 토큰이 가리키는 계정과 처음 로그인한 시각. authTime을 모르는 옛 토큰은 null이다. */
public record RefreshGrant(String accountId, Instant authTime) {

    public RefreshGrant {
        Objects.requireNonNull(accountId, "accountId");
    }
}
