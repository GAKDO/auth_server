// 이 파일이 확인하는 것: Redis에 저장된 리프레시 토큰 값 읽기(계정 + 처음 로그인 시각).
// 처음 로그인 시각은 "로그인 10분 안에만 비밀번호 없이 탈퇴" 규칙에 쓴다.

package com.gakdo.trace.auth.token.infra;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.gakdo.trace.auth.token.domain.RefreshGrant;

class RefreshGrantParseTest {

    // [상황] "계정|시각" 값, 시각이 없는 옛 값, 시각 자리가 깨진 값을 읽는다.
    // [기대] 계정과 시각을 읽고, 옛 값·깨진 값은 시각을 "모름"으로 둔다.
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
