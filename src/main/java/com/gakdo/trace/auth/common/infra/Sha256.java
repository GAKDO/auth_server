package com.gakdo.trace.auth.common.infra;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;

/** QR 토큰·페어링 코드·리프레시 토큰은 원문 대신 이 해시(16진수 소문자 64자)만 저장한다. */
public final class Sha256 {

    private Sha256() {
    }

    public static String hex(String value) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            return HexFormat.of().formatHex(digest.digest(value.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256을 쓸 수 없습니다", e);
        }
    }
}
