package com.gakdo.trace.auth.booth.application;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.booth.domain.ClientCredential;
import com.gakdo.trace.auth.booth.domain.ClientCredentialRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.domain.IssuedToken;
import com.gakdo.trace.auth.token.domain.TokenClaims;

/** 부스 client_id·secret → BOOTH JWT(scope=boothId, 1시간). (FR-AUTH-02) */
@Service
public class BoothTokenService {

    private final ClientCredentialRepository clients;
    private final PasswordEncoder passwordEncoder;
    private final JwtIssuer jwtIssuer;
    private final AuthProperties properties;
    private final String dummyHash;

    public BoothTokenService(ClientCredentialRepository clients, PasswordEncoder passwordEncoder,
                             JwtIssuer jwtIssuer, AuthProperties properties) {
        this.clients = clients;
        this.passwordEncoder = passwordEncoder;
        this.jwtIssuer = jwtIssuer;
        this.properties = properties;
        this.dummyHash = passwordEncoder.encode(java.util.UUID.randomUUID().toString());
    }

    @Transactional(readOnly = true)
    public BoothToken issue(String clientId, String clientSecret) {
        ClientCredential credential = clients.findByClientId(clientId).orElse(null);
        String hash = credential == null ? dummyHash : credential.getSecretHash();
        boolean matches = passwordEncoder.matches(clientSecret, hash);
        if (credential == null || !matches || !credential.isActive() || !credential.isBooth()) {
            throw new AuthException(ErrorCode.CLIENT_CREDENTIALS_INVALID);
        }
        IssuedToken token = jwtIssuer.issue(TokenClaims.booth(credential.getClientId(), properties.boothTokenTtl()));
        return new BoothToken(token, credential.getClientId());
    }

    public record BoothToken(IssuedToken token, String boothId) {
    }
}
