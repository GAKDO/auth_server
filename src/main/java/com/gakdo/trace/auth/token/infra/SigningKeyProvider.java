package com.gakdo.trace.auth.token.infra;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.config.AuthProperties;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;

/**
 * JWT 서명 키 하나를 들고 있다. JWT_PRIVATE_KEY는 PKCS#8 PEM을 base64 한 줄로 만든 값(PEM 원문도 받음)이다.
 * kid는 공개키의 RFC 7638 지문이라 키를 바꾸면 kid도 바뀌어 gateway 캐시가 새 키를 받으러 간다.
 */
@Component
public class SigningKeyProvider {

    private static final Logger log = LoggerFactory.getLogger(SigningKeyProvider.class);

    private final RSAKey rsaKey;

    public SigningKeyProvider(AuthProperties properties) {
        String configured = properties.jwtPrivateKey();
        if (configured == null || configured.isBlank()) {
            if (properties.requireConfiguredKey()) {
                throw new IllegalStateException("JWT_PRIVATE_KEY가 없습니다. trace-secrets에 서명 키를 넣어 주세요");
            }
            log.warn("JWT_PRIVATE_KEY가 없어 임시 서명 키를 만듭니다. 재시작하면 발급한 토큰이 모두 무효가 됩니다(로컬·테스트 전용)");
            this.rsaKey = withKid(generate());
        } else {
            this.rsaKey = withKid(parse(configured.trim()));
        }
    }

    /** 서명용(개인키 포함). auth-server 밖으로 내보내지 않는다. */
    public RSAKey signingKey() {
        return rsaKey;
    }

    /** JWKS에 싣는 공개키. */
    public RSAKey publicJwk() {
        return rsaKey.toPublicJWK();
    }

    public RSAPublicKey publicKey() {
        try {
            return rsaKey.toRSAPublicKey();
        } catch (JOSEException e) {
            throw new IllegalStateException("공개키를 읽을 수 없습니다", e);
        }
    }

    static RSAKey parse(String value) {
        String pem = value.startsWith("-----BEGIN")
                ? value
                : new String(Base64.getMimeDecoder().decode(value), StandardCharsets.US_ASCII);
        if (!pem.contains("BEGIN PRIVATE KEY")) {
            throw new IllegalStateException("JWT_PRIVATE_KEY는 PKCS#8(BEGIN PRIVATE KEY) 형식이어야 합니다");
        }
        String body = pem.replaceAll("-----(BEGIN|END) PRIVATE KEY-----", "").replaceAll("\\s", "");
        try {
            KeyFactory factory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privateKey = (RSAPrivateCrtKey) factory.generatePrivate(
                    new PKCS8EncodedKeySpec(Base64.getDecoder().decode(body)));
            RSAPublicKey publicKey = (RSAPublicKey) factory.generatePublic(
                    new RSAPublicKeySpec(privateKey.getModulus(), privateKey.getPublicExponent()));
            return new RSAKey.Builder(publicKey).privateKey(privateKey).build();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | ClassCastException
                 | IllegalArgumentException e) {
            throw new IllegalStateException("JWT_PRIVATE_KEY를 RSA 개인키로 읽을 수 없습니다", e);
        }
    }

    private static RSAKey generate() {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            var pair = generator.generateKeyPair();
            return new RSAKey.Builder((RSAPublicKey) pair.getPublic()).privateKey(pair.getPrivate()).build();
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("RSA 키를 만들 수 없습니다", e);
        }
    }

    private static RSAKey withKid(RSAKey key) {
        try {
            return new RSAKey.Builder(key)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyIDFromThumbprint()
                    .build();
        } catch (JOSEException e) {
            throw new IllegalStateException("kid를 만들 수 없습니다", e);
        }
    }
}
