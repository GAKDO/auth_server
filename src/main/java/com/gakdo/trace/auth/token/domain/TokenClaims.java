package com.gakdo.trace.auth.token.domain;

import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;

/**
 * 발급할 JWT의 내용. scope는 촬영·AGENT의 checkpointId, BOOTH의 boothId이고,
 * rentals는 CUSTOMER 액세스 토큰에만, rentalId는 촬영·AGENT 토큰에만, deviceSerial은 AGENT 토큰에만 넣는다
 * (설계서 "인증", decisions.md 11/2, contracts auth-server 0.2.0).
 * authTime은 사람이 실제로 로그인한 시각(auth_time)으로, 관리자·고객 토큰에만 넣고 재발급해도 바뀌지 않는다.
 */
public record TokenClaims(String subject, TokenRole role, String scope, List<String> rentals, String rentalId,
                          String deviceSerial, Duration ttl, Instant authTime) {

    public TokenClaims {
        Objects.requireNonNull(subject, "subject");
        Objects.requireNonNull(role, "role");
        Objects.requireNonNull(ttl, "ttl");
    }

    /** 로그인 시각을 붙인 사본. */
    public TokenClaims withAuthTime(Instant at) {
        return new TokenClaims(subject, role, scope, rentals, rentalId, deviceSerial, ttl, at);
    }

    public static TokenClaims admin(String accountId, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.ADMIN, null, null, null, null, ttl, null);
    }

    public static TokenClaims customer(String accountId, List<String> rentals, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.CUSTOMER, null, List.copyOf(rentals), null, null, ttl, null);
    }

    public static TokenClaims capture(String accountId, String checkpointId, String rentalId, Duration ttl) {
        return new TokenClaims(accountId, TokenRole.CUSTOMER, checkpointId, null, rentalId, null,
                ttl, null);
    }

    public static TokenClaims booth(String boothId, Duration ttl) {
        return new TokenClaims(boothId, TokenRole.BOOTH, boothId, null, null, null, ttl, null);
    }

    /**
     * 페어링 코드에는 밖에 보이는 ID가 없어 sub도 시점 publicId로 둔다.
     * deviceSerial은 관리자가 코드를 만들 때 정한 렌탈 기기 등록 시리얼로, diagnostics-server가 진단 JSON과 대조한다.
     */
    public static TokenClaims agent(String checkpointId, String rentalId, String deviceSerial, Duration ttl) {
        Objects.requireNonNull(deviceSerial, "deviceSerial");
        return new TokenClaims(checkpointId, TokenRole.AGENT, checkpointId, null, rentalId, deviceSerial,
                ttl, null);
    }
}
