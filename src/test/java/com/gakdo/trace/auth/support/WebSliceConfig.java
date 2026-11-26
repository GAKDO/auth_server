// 테스트 도구(테스트 자체는 아님): 컨트롤러만 띄우는 테스트에 운영과 같은 보안 규칙·토큰 발급기를 붙인다.

package com.gakdo.trace.auth.support;

import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Import;

import com.gakdo.trace.auth.account.api.RefreshCookies;
import com.gakdo.trace.auth.config.ClockConfig;
import com.gakdo.trace.auth.config.SecurityConfig;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

/** @WebMvcTest에 실제 보안 규칙과 JWT 발급기를 싣는다(DB·Redis 없이). */
// (도구) @TestConfiguration = 테스트에서만 쓰는 스프링 설정이라는 표시
@TestConfiguration
// (도구) @Import = 함께 띄울 부품을 고른다. 운영과 같은 보안 규칙·시계·서명 키·토큰 발급기·리프레시 쿠키 도구를 싣는다(DB·Redis 없이 보안까지 시험하려고)
@Import({SecurityConfig.class, ClockConfig.class, SigningKeyProvider.class, JwtIssuer.class, RefreshCookies.class})
public class WebSliceConfig {
}
