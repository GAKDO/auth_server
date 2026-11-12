package com.gakdo.trace.auth.token.infra;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.gakdo.trace.auth.token.domain.RefreshGrant;

class RefreshGrantParseTest {

    @Test
    @DisplayName("리프레시 토큰 값에서 계정과 처음 로그인 시각을 읽고, 시각이 없는 옛 값은 시각을 모르는 것으로 읽는다")
    void parsesAccountAndAuthTime() {
        assertThat(RedisRefreshTokenStore.parse("abcDEF123_-xyz0000000|1794000000"))
                .isEqualTo(new RefreshGrant("abcDEF123_-xyz0000000", Instant.ofEpochSecond(1_794_000_000L)));
        assertThat(RedisRefreshTokenStore.parse("abcDEF123_-xyz0000000"))
                .isEqualTo(new RefreshGrant("abcDEF123_-xyz0000000", null));
        assertThat(RedisRefreshTokenStore.parse("abcDEF123_-xyz0000000|oops"))
                .isEqualTo(new RefreshGrant("abcDEF123_-xyz0000000", null));
    }
}
