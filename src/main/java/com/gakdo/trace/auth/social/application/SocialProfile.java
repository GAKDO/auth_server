package com.gakdo.trace.auth.social.application;

import com.gakdo.trace.auth.social.domain.SocialProvider;

/**
 * 제공자에게서 받은 사용자 정보. email은 제공자가 인증했다고 알려 준 주소만 담고, 없으면 null.
 * name은 받지 못하면 null.
 */
public record SocialProfile(SocialProvider provider, String subject, String email, String name) {
}
