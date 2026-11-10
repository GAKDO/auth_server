package com.gakdo.trace.auth.social.application;

import java.util.Optional;

import com.gakdo.trace.auth.social.domain.SocialProvider;

/** 로그인 시작 때 만든 state를 한 번만 쓰게 저장한다(CSRF 방지). */
public interface OAuthStateStore {

    /** 새 state를 만들어 저장하고 원문을 돌려준다. */
    String issue(SocialProvider provider, String next);

    /** state를 꺼내고 지운다. 없거나 만료됐거나 제공자가 다르면 빈 값. */
    Optional<PendingLogin> consume(SocialProvider provider, String state);

    /** 시작할 때 저장한 돌아갈 화면 경로. */
    record PendingLogin(String next) {
    }
}
