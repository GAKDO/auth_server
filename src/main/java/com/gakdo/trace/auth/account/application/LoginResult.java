package com.gakdo.trace.auth.account.application;

import com.gakdo.trace.auth.account.domain.AccountRole;
import com.gakdo.trace.auth.token.domain.IssuedToken;

/** 로그인·재발급 결과. 리프레시 원문은 컨트롤러가 쿠키로만 내보낸다. */
public record LoginResult(IssuedToken accessToken, String refreshToken, AccountRole role) {
}
