package com.gakdo.trace.auth.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;

import com.gakdo.trace.auth.config.ClockConfig;
import com.gakdo.trace.auth.config.SecurityConfig;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

/** @WebMvcTest에 실제 보안 규칙과 JWT 발급기를 싣는다(DB·Redis 없이). */
@TestConfiguration
@Import({SecurityConfig.class, ClockConfig.class, SigningKeyProvider.class, JwtIssuer.class})
public class WebSliceConfig {
}
