package com.gakdo.trace.auth.pairing.application;

import java.time.Clock;
import java.time.Instant;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.domain.RateLimitedException;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.pairing.domain.PairingCode;
import com.gakdo.trace.auth.pairing.domain.PairingCodeRepository;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.domain.IssuedToken;
import com.gakdo.trace.auth.token.domain.TokenClaims;

/** 진단 에이전트 페어링 코드 발급·교환(FR-AUTH-02). 코드는 5분 1회용이고 SHA-256만 저장한다. 틀린 코드는 전역 실패 한도로 센다. */
@Service
public class PairingService {

    private static final int MAX_DRAWS = 5;

    private final PairingCodeRepository codes;
    private final SecureTokens tokens;
    private final JwtIssuer jwtIssuer;
    private final AuthProperties properties;
    private final Clock clock;
    private final PairingFailureGuard failures;

    public PairingService(PairingCodeRepository codes, SecureTokens tokens, JwtIssuer jwtIssuer,
                          AuthProperties properties, Clock clock, PairingFailureGuard failures) {
        this.failures = failures;
        this.codes = codes;
        this.tokens = tokens;
        this.jwtIssuer = jwtIssuer;
        this.properties = properties;
        this.clock = clock;
    }

    @Transactional
    public IssuedCode create(String rentalId, String checkpointId, String deviceSerial) {
        Instant now = clock.instant();
        for (int draw = 0; draw < MAX_DRAWS; draw++) {
            String code = tokens.sixDigitCode();
            String hash = Sha256.hex(code);
            // 같은 값의 유효한 코드가 있으면 어느 시점인지 고를 수 없으니 다시 뽑는다
            if (codes.existsByCodeHashAndUsedAtIsNullAndExpiresAtAfter(hash, now)) {
                continue;
            }
            Instant expiresAt = now.plus(properties.pairingCodeTtl());
            codes.save(new PairingCode(rentalId, checkpointId, deviceSerial, hash, expiresAt, now));
            return new IssuedCode(code, expiresAt);
        }
        throw new IllegalStateException("겹치지 않는 페어링 코드를 뽑지 못했습니다");
    }

    @Transactional
    public AgentToken exchange(String code) {
        // 조회 전에 시도를 원자적으로 잡는다. 막는 동안은 맞는 코드도 거절한다(대입 중 우연히 맞힌 코드를 받지 않으려고)
        PairingFailureGuard.Attempt attempt = failures.tryAcquire();
        if (attempt.blockedForSeconds() > 0) {
            throw new RateLimitedException(attempt.blockedForSeconds());
        }
        Instant now = clock.instant();
        PairingCode pairing = codes.findFirstByCodeHashOrderByCreatedAtDesc(Sha256.hex(code))
                .orElse(null);
        if (pairing == null) {
            failures.recordFailure(attempt);
            throw new AuthException(ErrorCode.PAIRING_CODE_INVALID);
        }
        // 있는 코드였으니 추측이 아니다. 잡아 둔 시도를 같은 창에서 푼다
        failures.refund(attempt);
        // V2·V3 전에 만든 코드는 렌탈·시리얼이 없어 토큰을 만들 수 없다(어차피 5분 뒤 만료)
        if (pairing.getRentalId() == null || pairing.getDeviceSerial() == null) {
            throw new AuthException(ErrorCode.PAIRING_CODE_INVALID);
        }
        if (!pairing.isUsableAt(now) || codes.markUsed(pairing.getId(), now) != 1) {
            throw new AuthException(ErrorCode.PAIRING_CODE_EXPIRED);
        }
        IssuedToken token = jwtIssuer.issue(TokenClaims.agent(pairing.getCheckpointId(),
                pairing.getRentalId(), pairing.getDeviceSerial(), properties.agentTokenTtl()));
        return new AgentToken(token, pairing.getRentalId(), pairing.getCheckpointId(), pairing.getDeviceSerial());
    }

    public record IssuedCode(String code, Instant expiresAt) {
    }

    public record AgentToken(IssuedToken token, String rentalId, String checkpointId, String deviceSerial) {
    }
}
