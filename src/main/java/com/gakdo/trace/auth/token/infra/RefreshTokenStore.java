package com.gakdo.trace.auth.token.infra;

import java.time.Instant;
import java.util.Optional;

import com.gakdo.trace.auth.token.domain.RefreshGrant;

/** 리프레시 토큰 저장소. 원문은 쿠키에만 있고 저장소는 해시를 키로 쓴다. */
public interface RefreshTokenStore {

    /** 새 리프레시 토큰을 만들어 계정과 로그인 시각에 묶고 원문을 돌려준다. 재발급해도 authTime은 처음 값을 이어 간다. */
    String issue(String accountId, Instant authTime);

    /** 토큰을 한 번만 받아들인다. 받아들이면 지우고 계정·로그인 시각을, 없거나 이미 쓴 토큰이면 빈 값을 준다. */
    Optional<RefreshGrant> consume(String token);

    void revoke(String token);

    /** 계정의 리프레시 토큰을 모두 지운다(AU2 비밀번호 재설정·탈퇴). */
    void revokeAll(String accountId);
}
