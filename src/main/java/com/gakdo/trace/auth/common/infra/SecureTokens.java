package com.gakdo.trace.auth.common.infra;

import java.security.SecureRandom;
import java.util.Base64;

import org.springframework.stereotype.Component;

/** 1회용 토큰과 6자리 코드를 만든다. 테스트에서 값을 정할 수 있게 빈으로 둔다. */
@Component
public class SecureTokens {

    private final SecureRandom random = new SecureRandom();

    /** 32바이트 난수를 base64url(패딩 없음, 43자)로. QR 토큰·리프레시 토큰에 쓴다. */
    public String opaqueToken() {
        byte[] bytes = new byte[32];
        random.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }

    /** 000000~999999 페어링 코드. */
    public String sixDigitCode() {
        return String.format("%06d", random.nextInt(1_000_000));
    }
}
