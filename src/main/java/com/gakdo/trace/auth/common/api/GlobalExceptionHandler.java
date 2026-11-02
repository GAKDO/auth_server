package com.gakdo.trace.auth.common.api;

import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ProblemDetail;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.ErrorResponse;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;

import jakarta.servlet.http.HttpServletRequest;

/** 모든 오류를 application/problem+json + code로 바꾸는 한 곳. */
@RestControllerAdvice
public class GlobalExceptionHandler {

    private static final Logger log = LoggerFactory.getLogger(GlobalExceptionHandler.class);

    @ExceptionHandler(AuthException.class)
    ProblemDetail handleAuth(AuthException e, HttpServletRequest request) {
        return Problems.of(e.code(), null, request.getRequestURI());
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    ProblemDetail handleInvalid(MethodArgumentNotValidException e, HttpServletRequest request) {
        ProblemDetail problem = Problems.of(ErrorCode.VALIDATION_FAILED, null, request.getRequestURI());
        // 값은 싣지 않는다(비밀번호가 섞일 수 있음). 필드와 이유만 준다
        List<Map<String, String>> errors = e.getBindingResult().getFieldErrors().stream()
                .map(f -> Map.of("field", f.getField(), "message", String.valueOf(f.getDefaultMessage())))
                .toList();
        problem.setProperty("errors", errors);
        return problem;
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    ProblemDetail handleUnreadable(HttpMessageNotReadableException e, HttpServletRequest request) {
        return Problems.of(ErrorCode.VALIDATION_FAILED, "본문을 읽을 수 없습니다", request.getRequestURI());
    }

    @ExceptionHandler(Exception.class)
    ProblemDetail handleUnexpected(Exception e, HttpServletRequest request) {
        if (e instanceof ErrorResponse spring) {
            // 404·405·415 같은 스프링 표준 오류는 상태를 그대로 두고 code만 더한다
            ProblemDetail body = spring.getBody();
            body.setProperty("code", body.getStatus() == 404 ? "NOT_FOUND" : ErrorCode.VALIDATION_FAILED.name());
            return body;
        }
        log.error("처리하지 못한 오류: {} {}", request.getMethod(), request.getRequestURI(), e);
        return Problems.of(ErrorCode.INTERNAL_ERROR, null, request.getRequestURI());
    }
}
