package com.gakdo.trace.auth.token.api;

import java.util.Map;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.gakdo.trace.auth.token.infra.SigningKeyProvider;
import com.nimbusds.jose.jwk.JWKSet;

/** gateway와 각 서버가 JWT 서명을 검증할 공개키(FR-AUTH-03의 전제). */
@RestController
public class JwksController {

    private final SigningKeyProvider keys;

    public JwksController(SigningKeyProvider keys) {
        this.keys = keys;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, Object> jwks() {
        return new JWKSet(keys.publicJwk()).toJSONObject();
    }
}
