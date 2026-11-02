package com.gakdo.trace.auth.common.api;

import java.net.URI;

import org.springframework.http.ProblemDetail;

import com.gakdo.trace.auth.common.domain.ErrorCode;

/** RFC 9457 본문에 contracts의 code를 더한다. 컨트롤러 조언과 보안 필터가 같은 모양을 쓴다. */
public final class Problems {

    private Problems() {
    }

    public static ProblemDetail of(ErrorCode code, String detail, String instance) {
        ProblemDetail problem = ProblemDetail.forStatus(code.status());
        problem.setTitle(code.title());
        problem.setProperty("code", code.name());
        if (detail != null) {
            problem.setDetail(detail);
        }
        if (instance != null) {
            problem.setInstance(URI.create(instance));
        }
        return problem;
    }
}
