package com.gakdo.trace.auth.token.application;

import java.time.Clock;
import java.time.Instant;
import java.util.Date;

import org.springframework.stereotype.Component;

import com.gakdo.trace.auth.common.infra.NanoId;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.token.domain.IssuedToken;
import com.gakdo.trace.auth.token.domain.TokenClaims;
import com.gakdo.trace.auth.token.infra.SigningKeyProvider;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

/** RS256 JWT를 만든다. 클레임은 iss·sub·role·scope·rentals·rentalId·deviceSerial·iat·exp·jti(contracts common.yaml bearerJwt). */
@Component
public class JwtIssuer {

    private final SigningKeyProvider keys;
    private final AuthProperties properties;
    private final Clock clock;
    private final RSASSASigner signer;

    public JwtIssuer(SigningKeyProvider keys, AuthProperties properties, Clock clock) {
        this.keys = keys;
        this.properties = properties;
        this.clock = clock;
        try {
            this.signer = new RSASSASigner(keys.signingKey());
        } catch (JOSEException e) {
            throw new IllegalStateException("서명기를 만들 수 없습니다", e);
        }
    }

    public IssuedToken issue(TokenClaims claims) {
        Instant now = clock.instant();
        Instant expiresAt = now.plus(claims.ttl());
        JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                .issuer(properties.issuer())
                .subject(claims.subject())
                .claim("role", claims.role().name())
                .issueTime(Date.from(now))
                .expirationTime(Date.from(expiresAt))
                .jwtID(NanoId.next());
        if (claims.scope() != null) {
            builder.claim("scope", claims.scope());
        }
        if (claims.rentals() != null) {
            builder.claim("rentals", claims.rentals());
        }
        if (claims.rentalId() != null) {
            builder.claim("rentalId", claims.rentalId());
        }
        if (claims.deviceSerial() != null) {
            builder.claim("deviceSerial", claims.deviceSerial());
        }
        JWSHeader header = new JWSHeader.Builder(JWSAlgorithm.RS256)
                .type(JOSEObjectType.JWT)
                .keyID(keys.signingKey().getKeyID())
                .build();
        SignedJWT jwt = new SignedJWT(header, builder.build());
        try {
            jwt.sign(signer);
        } catch (JOSEException e) {
            throw new IllegalStateException("JWT 서명에 실패했습니다", e);
        }
        return new IssuedToken(jwt.serialize(), claims.ttl().toSeconds());
    }
}
