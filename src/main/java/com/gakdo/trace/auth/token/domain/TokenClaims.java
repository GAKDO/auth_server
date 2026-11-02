package com.gakdo.trace.auth.token.domain;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * 발급할 JWT의 내용. scope는 촬영·AGENT의 checkpointId, BOOTH의 boothId이고,
 * rentals는 CUSTOMER 액세스 토큰에만, rentalId는 촬영·AGENT 토큰에만 넣는다(설계서 "인증", decisions.md 11/2).
 */
public record TokenClaims(String subject, TokenRole role, String scope, List<String> rentals, String rentalId,
                          Duration ttl) {

    public TokenClaims {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(ttl, "ttl");
    }

    public static TokenClaims admin(String accountId, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.ADMIN, null, null, null, ttl);
    }

    public static TokenClaims customer(String accountId, List<String> rentals, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.CUSTOMER, null, List.copyOf(rentals), null, ttl);
    }

    public static TokenClaims capture(String accountId, String checkpointId, String rentalId, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.CUSTOMER, checkpointId, null, rentalId,
                ttl);
    }

    public static TokenClaims booth(String boothId, Duration ttl) {
        return new TokenClaims(boothId, TokenRole.BOOTH, boothId, null, null, ttl);
    }

    /** 페어링 코드에는 밖에 보이는 ID가 없어 sub도 시점 publicId로 둔다. */
    public static TokenClaims agent(String checkpointId, String rentalId, Duration ttl) {
        return new TokenClaims(checkpointId, TokenRole.AGENT, checkpointId, null, rentalId,
                ttl);
    }
}
