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
    // (도구) @Test = JUnit에게 "이 메서드가 테스트 하나"라고 알리는 표시. @DisplayName = 결과 화면에 보일 한글 이름
    @Test
    @DisplayName("JWT_PRIVATE_KEY는 base64 한 줄 PKCS#8 PEM으로 읽고 kid는 지문이라 같은 키면 같다")
    void readsBase64Pem() throws Exception {
        // 준비: RSA 열쇠 만들기 도구를 준비한다(시험할 때마다 새 열쇠를 만들려고)
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        // 열쇠 길이를 2048비트로 정한다
        generator.initialize(2048);
        // 실행할 때 만든 키로 PEM을 조립한다(머리글 문자열을 그대로 두면 gitleaks가 키로 본다)
        String label = "PRIVATE " + "KEY";
        // 새로 만든 비밀 열쇠를 PEM 원문 형식(머리글 + base64 + 꼬리글)으로 만든다
        String pem = "-----BEGIN " + label + "-----\n"
                + Base64.getMimeEncoder().encodeToString(generator.generateKeyPair().getPrivate().getEncoded())
                + "\n-----END " + label + "-----\n";
        // 같은 PEM 원문을 통째로 base64 한 줄로 바꾼다(환경 변수에 넣기 쉬운 형식)
        String oneLine = Base64.getEncoder().encodeToString(pem.getBytes(StandardCharsets.US_ASCII));

        // 실행: base64 한 줄 형식으로 서명 열쇠를 읽는다
        SigningKeyProvider a = new SigningKeyProvider(properties(oneLine, true));
        // 실행: PEM 원문 형식으로 같은 열쇠를 읽는다
        SigningKeyProvider b = new SigningKeyProvider(properties(pem, true));

        // (도구) assertThat(값).검사() = "값이 이래야 한다"를 확인하는 AssertJ 도구. isNotBlank() = 비어 있지 않아야, isEqualTo(값) = 그 값과 같아야 통과
        // 확인: 열쇠 이름(kid)이 비어 있지 않고 두 형식에서 같아야 한다 = 같은 열쇠면 같은 이름
        assertThat(a.publicJwk().getKeyID()).isNotBlank().isEqualTo(b.publicJwk().getKeyID());
        // (도구) isFalse() = 값이 false여야 통과
        // 확인: 밖에 내보이는 공개 열쇠에는 비밀 부분이 없어야 한다
        assertThat(a.publicJwk().isPrivate()).isFalse();
    }

    // [상황] 학교 서버(school) 설정에서 열쇠가 비어 있다. 다른 경우는 로컬 개발 환경이다.
    // [기대] 학교 서버면 켜지지 않고 멈춘다(임시 열쇠로 운영되는 사고 방지). 로컬이면 임시 열쇠를 만든다.
    @Test
    @DisplayName("school 프로필에서 키가 없으면 시작하지 않고, 로컬에서는 임시 키를 만든다")
    void missingKey() {
        // 준비: 열쇠가 꼭 있어야 하는(학교 서버) 설정인데 열쇠가 비어 있게 만든다
        var schoolWithoutKey = properties("", true);
        // (도구) assertThatThrownBy(() -> 코드).isInstanceOf(예외) = 그 코드를 돌리면 이 종류의 예외가 나야 통과
        // 실행+확인: 그 설정으로 열쇠 읽기를 만들면
        assertThatThrownBy(() -> new SigningKeyProvider(schoolWithoutKey))
                // 시작을 막는 예외가 나야 한다 = 임시 열쇠로 운영되는 사고 방지
                .isInstanceOf(IllegalStateException.class);
        // (도구) isNotNull() = 값이 있어야(null 아님) 통과
        // 실행+확인: 로컬(열쇠 필수 아님)에서는 열쇠가 없어도 임시 열쇠를 만들어 공개 열쇠가 있어야 한다
        assertThat(new SigningKeyProvider(properties("", false)).publicKey()).isNotNull();
    }

    // [상황] 열쇠 자리에 엉뚱한 값("hello")을 넣는다.
    // [기대] 거부한다.
    @Test
    @DisplayName("PKCS#8이 아닌 값은 거부한다")
    void rejectsGarbage() {
        // 준비: 열쇠가 아닌 글자("hello")를 base64로 바꾼다
        String notPem = Base64.getEncoder().encodeToString("hello".getBytes(StandardCharsets.US_ASCII));
        // 그 값을 열쇠 자리에 넣은 설정을 만든다
        var garbage = properties(notPem, false);
        // 실행+확인: 그 설정으로 열쇠를 읽으면
        assertThatThrownBy(() -> new SigningKeyProvider(garbage))
                // 열쇠가 아니라고 예외가 나야 한다
                .isInstanceOf(IllegalStateException.class);
    }

    // 테스트 도구: 열쇠 값과 "열쇠 필수 여부"만 바꾼 인증 설정을 만든다
    static AuthProperties properties(String key, boolean required) {
        // 시험에 상관없는 유효 시간들은 모두 5분으로 둔다
        Duration d = Duration.ofMinutes(5);
        // 발급자 trace, 받은 열쇠·필수 여부, Redis 접두사 등을 넣은 설정을 돌려준다
        return new AuthProperties("trace", key, required, "trace:", "http://localhost:8315", d, d, d, d, d, d, d,
                true, null, null, null);
    }
}
