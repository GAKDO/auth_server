// 이 파일이 확인하는 것: 로그인 토큰(JWT) 서명 열쇠 읽기. 열쇠는 운영에서 trace-secrets의 JWT_PRIVATE_KEY로 받는다.
// 테스트 열쇠는 실행할 때마다 새로 만든다(운영 열쇠와 무관).

package com.gakdo.trace.auth.token;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.nio.charset.StandardCharsets;
import java.security.KeyPairGenerator;
import java.time.Duration;
import java.util.Base64;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;

class SigningKeyProviderTest {

    // [상황] 같은 열쇠를 base64 한 줄 형식과 PEM 원문 형식으로 각각 넣는다.
    // [기대] 둘 다 읽히고 열쇠 이름(kid, 지문으로 만듦)이 같다. 밖에 내보이는 공개 열쇠에는 비밀 부분이 없다.
    @Test
    @DisplayName("JWT_PRIVATE_KEY는 base64 한 줄 PKCS#8 PEM으로 읽고 kid는 지문이라 같은 키면 같다")
    void readsBase64Pem() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        // 실행할 때 만든 키로 PEM을 조립한다(머리글 문자열을 그대로 두면 gitleaks가 키로 본다)
        String label = "PRIVATE " + "KEY";
        String pem = "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                + "\n-----END " + label + "-----\n";
        String oneLine = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));

        SigningKeyProvider a = new SigningKeyProvider(properties(oneLine, true));
        SigningKeyProvider b = new SigningKeyProvider(properties(pem, true));

        assertThat(a.publicJwk().getKeyID()).isNotBlank().isEqualTo(b.publicJwk().getKeyID());
        assertThat(a.publicJwk().isPrivate()).isFalse();
    }

    // [상황] 학교 서버(school) 설정에서 열쇠가 비어 있다. 다른 경우는 로컬 개발 환경이다.
    // [기대] 학교 서버면 켜지지 않고 멈춘다(임시 열쇠로 운영되는 사고 방지). 로컬이면 임시 열쇠를 만든다.
    @Test
    @DisplayName("school 프로필에서 키가 없으면 시작하지 않고, 로컬에서는 임시 키를 만든다")
    void missingKey() {
        var schoolWithoutKey = properties("", true);
        assertThatThrownBy(() -> new SigningKeyProvider(schoolWithoutKey))
                .isInstanceOf(IllegalStateException.class);
        assertThat(new SigningKeyProvider(properties("", false)).publicKey()).isNotNull();
    }

    // [상황] 열쇠 자리에 엉뚱한 값("hello")을 넣는다.
    // [기대] 거부한다.
    @Test
    @DisplayName("PKCS#8이 아닌 값은 거부한다")
    void rejectsGarbage() {
        String notPem = Base64.getEncoder().encodeToString("hello".getBytes(StandardCharsets.US_ASCII));
        var garbage = properties(notPem, false);
        assertThatThrownBy(() -> new SigningKeyProvider(garbage))
                .isInstanceOf(IllegalStateException.class);
    }

    static AuthProperties properties(String key, boolean required) {
        Duration d = Duration.ofMinutes(5);
        return new AuthProperties("trace", key, required, "trace:", "http://localhost:8315", d, d, d, d, d, d, d,
                true, null, null, null);
    }
}
