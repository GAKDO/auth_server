package com.gakdo.trace.auth.social.application;

import com.gakdo.trace.auth.social.domain.SocialProvider;

/** 제공자와 통신하는 부분(code → 토큰 → 사용자 정보). 테스트에서 바꿔 끼운다. */
public interface SocialProviderClient {

    /**
     * 콜백으로 받은 code를 토큰으로 바꾸고 사용자 정보를 읽는다.
     *
     * @throws SocialLoginException 제공자가 거절하거나 응답을 읽지 못하면 PROVIDER_ERROR
     */
    SocialProfile fetchProfile(SocialProvider provider, String code, String redirectUri, String state);
}
