package com.gakdo.trace.auth.social.api;

import java.util.List;

/** contracts SocialProvidersResponse: 지금 켜진 제공자(GOOGLE·GITHUB·KAKAO·NAVER) 목록. */
public record SocialProvidersResponse(List<String> providers) {
}
