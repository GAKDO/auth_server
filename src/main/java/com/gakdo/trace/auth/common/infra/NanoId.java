package com.gakdo.trace.auth.common.infra;

import java.security.SecureRandom;

/**
 * 밖에 보이는 ID(publicId, JWT jti)를 만든다. NanoID 기본 알파벳(A-Za-z0-9_-) 21자, 약 126비트.
 * DB 기본 키(bigint)는 순번이라 밖에 내보내지 않는다(헌법 1.1.0, decisions.md 11/2).
 */
public final class NanoId {

    public static final String PATTERN = "^[A-Za-z0-9_-]{21}$";
    private static final char[] ALPHABET =
            "useandom-26T198340PX75pxJACKVERYMINDBUSHWOLF_GQZbfghjklqvwyzrict".toCharArray();
    private static final int SIZE = 21;
    private static final SecureRandom RANDOM = new SecureRandom();

    private NanoId() {
    }

    public static String next() {
        byte[] bytes = new byte[SIZE];
        RANDOM.nextBytes(bytes);
        char[] id = new char[SIZE];
        for (int i = 0; i < SIZE; i++) {
            // 알파벳이 64자라 하위 6비트로 고르면 치우침이 없다
            id[i] = ALPHABET[bytes[i] & 63];
        }
        return new String(id);
    }
}
