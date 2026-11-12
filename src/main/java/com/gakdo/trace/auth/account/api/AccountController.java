package com.gakdo.trace.auth.account.api;

import java.time.Instant;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gakdo.trace.auth.account.application.PasswordResetService;
import com.gakdo.trace.auth.account.application.SignupService;
import com.gakdo.trace.auth.account.application.WithdrawService;

import jakarta.validation.Valid;

/** 고객 가입·이메일 인증·재발송·비밀번호 재설정·탈퇴(AU2, contracts auth-server.yaml). */
@RestController
@RequestMapping("/api/v1/auth")
public class AccountController {

    private final SignupService signupService;
    private final PasswordResetService passwordResetService;
    private final WithdrawService withdrawService;

    public AccountController(SignupService signupService, PasswordResetService passwordResetService,
                             WithdrawService withdrawService) {
        this.signupService = signupService;
        this.passwordResetService = passwordResetService;
        this.withdrawService = withdrawService;
    }

    @PostMapping("/signup")
    public ResponseEntity<SignupResponse> signup(@Valid @RequestBody SignupRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(SignupResponse.from(signupService.signup(
                request.email(), request.password(), request.name(), request.privacyAgreed())));
    }

    @PostMapping("/email/verify")
    public ResponseEntity<Void> verifyEmail(@Valid @RequestBody EmailVerifyRequest request) {
        signupService.verify(request.email(), request.code());
        return ResponseEntity.noContent().build();
    }

    @PostMapping("/email/resend")
    public ResponseEntity<Void> resend(@Valid @RequestBody EmailOnlyRequest request) {
        signupService.resend(request.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/password/reset-request")
    public ResponseEntity<Void> requestReset(@Valid @RequestBody EmailOnlyRequest request) {
        passwordResetService.requestReset(request.email());
        return ResponseEntity.accepted().build();
    }

    @PostMapping("/password/reset")
    public ResponseEntity<Void> reset(@Valid @RequestBody PasswordResetRequest request) {
        passwordResetService.reset(request.email(), request.code(), request.newPassword());
        return ResponseEntity.noContent().build();
    }

    @DeleteMapping("/me")
    public ResponseEntity<Void> withdraw(@AuthenticationPrincipal Jwt jwt, @Valid @RequestBody WithdrawRequest request) {
        withdrawService.withdraw(jwt.getSubject(), request.password(), authTimeOf(jwt));
        return ResponseEntity.noContent().build();
    }

    /** 로그인 시각(auth_time, 초). 없거나 숫자가 아니면 모르는 것으로 본다. */
    private static Instant authTimeOf(Jwt jwt) {
        Object value = jwt.getClaim("auth_time");
        if (value instanceof Number number) {
            return Instant.ofEpochSecond(number.longValue());
        }
        if (value instanceof Instant instant) {
            return instant;
        }
        return null;
    }
}
