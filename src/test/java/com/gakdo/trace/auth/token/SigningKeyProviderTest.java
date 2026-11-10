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

    @Test
    @DisplayName("school 프로필에서 키가 없으면 시작하지 않고, 로컬에서는 임시 키를 만든다")
    void missingKey() {
        var schoolWithoutKey = properties("", true);
        assertThatThrownBy(() -> new SigningKeyProvider(schoolWithoutKey))
                .isInstanceOf(IllegalStateException.class);
        assertThat(new SigningKeyProvider(properties("", false)).publicKey()).isNotNull();
    }

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
