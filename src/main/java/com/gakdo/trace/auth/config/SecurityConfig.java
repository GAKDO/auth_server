package com.gakdo.trace.auth.config;

import java.io.IOException;
import java.util.Collection;
import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.gakdo.trace.auth.common.api.Problems;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * auth-server 자신의 보호 경로를 자기 공개키로 검증한다(gateway도 같은 JWKS로 검증하지만 한 번 더 막는다).
 * 촬영 JWT(role CUSTOMER + scope)는 ROLE_CAPTURE만 받아 일반 고객 경로(/me·로그아웃·QR 교환)를 쓸 수 없다.
 */
@Configuration
public class SecurityConfig {

    static final String ROLE_CAPTURE = "ROLE_CAPTURE";

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http, ObjectMapper objectMapper) throws Exception {
        http
                .csrf(csrf -> csrf.disable()) // 무상태 Bearer. 리프레시 쿠키는 SameSite=Strict + Path 한정
                .sessionManagement(s -> s.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(HttpMethod.GET, "/api/v1/auth/ping", "/.well-known/jwks.json",
                                "/actuator/health/**", "/actuator/info").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/login", "/api/v1/auth/refresh",
                                "/api/v1/auth/booth/token", "/api/v1/auth/pairing-codes/exchange").permitAll()
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/capture-links/exchange").hasRole("CUSTOMER")
                        .requestMatchers(HttpMethod.POST, "/api/v1/auth/capture-links", "/api/v1/auth/pairing-codes")
                        .hasRole("ADMIN")
                        .requestMatchers("/api/v1/auth/me", "/api/v1/auth/logout").hasAnyRole("ADMIN", "CUSTOMER")
                        .requestMatchers("/error").permitAll()
                        .anyRequest().authenticated())
                .oauth2ResourceServer(rs -> rs
                        .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter()))
                        .authenticationEntryPoint((req, res, e) ->
                                writeProblem(objectMapper, req, res, ErrorCode.UNAUTHENTICATED))
                        .accessDeniedHandler((req, res, e) ->
                                writeProblem(objectMapper, req, res, ErrorCode.FORBIDDEN)))
                .exceptionHandling(ex -> ex
                        .authenticationEntryPoint((req, res, e) ->
                                writeProblem(objectMapper, req, res, ErrorCode.UNAUTHENTICATED))
                        .accessDeniedHandler((req, res, e) ->
                                writeProblem(objectMapper, req, res, ErrorCode.FORBIDDEN)));
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder(SigningKeyProvider keys, AuthProperties properties) {
        NimbusJwtDecoder decoder = NimbusJwtDecoder.withPublicKey(keys.publicKey())
                .signatureAlgorithm(SignatureAlgorithm.RS256)
                .build();
        decoder.setJwtValidator(new DelegatingOAuth2TokenValidator<>(
                JwtValidators.createDefaultWithIssuer(properties.issuer())));
        return decoder;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(SecurityConfig::authorities);
        return converter;
    }

    /** role 클레임 → ROLE_<role>. 촬영 JWT(CUSTOMER + scope)는 ROLE_CAPTURE로 바꾼다. */
    static Collection<GrantedAuthority> authorities(Jwt jwt) {
        String role = jwt.getClaimAsString("role");
        if (role == null) {
            return List.of();
        }
        if ("CUSTOMER".equals(role) && jwt.hasClaim("scope")) {
            return List.of(new SimpleGrantedAuthority(ROLE_CAPTURE));
        }
        return List.of(new SimpleGrantedAuthority("ROLE_" + role));
    }

    private static void writeProblem(ObjectMapper objectMapper, HttpServletRequest request,
                                     HttpServletResponse response, ErrorCode code) throws IOException {
        ProblemDetail problem = Problems.of(code, null, request.getRequestURI());
        response.setStatus(code.status().value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.setCharacterEncoding("UTF-8");
        objectMapper.writeValue(response.getOutputStream(), problem);
    }
}
