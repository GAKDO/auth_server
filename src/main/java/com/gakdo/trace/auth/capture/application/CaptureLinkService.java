package com.gakdo.trace.auth.capture.application;

import java.time.Clock;
import java.time.Instant;

import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.AccountRepository;
import com.gakdo.trace.auth.account.domain.AccountStatus;
import com.gakdo.trace.auth.account.domain.RentalAccess;
import com.gakdo.trace.auth.account.domain.RentalAccessRepository;
import com.gakdo.trace.auth.capture.domain.CaptureLink;
import com.gakdo.trace.auth.capture.domain.CaptureLinkRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.AuthProperties;
import com.gakdo.trace.auth.receipt.application.ReceiptService;
import com.gakdo.trace.auth.token.application.JwtIssuer;
import com.gakdo.trace.auth.token.domain.IssuedToken;
import com.gakdo.trace.auth.token.domain.TokenClaims;

/**
 * 수령 QR 링크 발급(FR-RNT-04)과 교환(FR-AUTH-02, FR-USR-02).
 * 교환하면 그 시점만 쓰는 촬영 JWT를 주고 렌탈을 고객 계정에 연결한다(이후 로그인 JWT의 rentals에 들어감).
 */
@Service
public class CaptureLinkService {

    private final CaptureLinkRepository links;
    private final AccountRepository accounts;
    private final RentalAccessRepository rentalAccesses;
    private final SecureTokens tokens;
    private final JwtIssuer jwtIssuer;
    private final AuthProperties properties;
    private final ReceiptService receipts;
    private final Clock clock;

    public CaptureLinkService(CaptureLinkRepository links, AccountRepository accounts,
                              RentalAccessRepository rentalAccesses,
                              SecureTokens tokens, JwtIssuer jwtIssuer, AuthProperties properties,
                              ReceiptService receipts, Clock clock) {
        this.links = links;
        this.accounts = accounts;
        this.rentalAccesses = rentalAccesses;
        this.tokens = tokens;
        this.jwtIssuer = jwtIssuer;
        this.properties = properties;
        this.receipts = receipts;
        this.clock = clock;
    }

    @Transactional
    public IssuedLink create(String rentalId, String checkpointId) {
        Instant now = clock.instant();
        String token = tokens.opaqueToken();
        Instant expiresAt = now.plus(properties.captureLinkTtl());
        links.save(new CaptureLink(rentalId, checkpointId, Sha256.hex(token), expiresAt, now));
        String url = UriComponentsBuilder.fromUriString(properties.webPublicUrl())
                .path("/capture")
                .queryParam("t", token)
                .build()
                .toUriString();
        return new IssuedLink(url, expiresAt);
    }

    @Transactional
    public CaptureToken exchange(String accountPublicId, String token) {
        Instant now = clock.instant();
        Account account = accounts.findByPublicId(accountPublicId)
                .filter(a -> a.getStatus() == AccountStatus.ACTIVE)
                .orElseThrow(() -> new AuthException(ErrorCode.UNAUTHENTICATED));
        Long accountId = account.getId();
        CaptureLink link = links.findByTokenHash(Sha256.hex(token))
                .filter(l -> l.isUsableAt(now))
                .orElseThrow(() -> new AuthException(ErrorCode.CAPTURE_LINK_INVALID));
        RentalAccess existing = rentalAccesses.findByRentalId(link.getRentalId()).orElse(null);
        if (existing != null && !existing.getAccountId().equals(accountId)) {
            throw new AuthException(ErrorCode.RENTAL_LINKED_TO_OTHER);
        }
        if (links.markUsed(link.getId(), now) != 1) {
            throw new AuthException(ErrorCode.CAPTURE_LINK_INVALID);
        }
        if (existing == null) {
            link(accountId, link.getRentalId(), now);
        }
        IssuedToken jwt = jwtIssuer.issue(TokenClaims.capture(accountPublicId, link.getCheckpointId(), link.getRentalId(),
                properties.captureTokenTtl()));
        return new CaptureToken(jwt, link.getRentalId(), link.getCheckpointId());
    }

    private void link(Long accountId, String rentalId, Instant now) {
        RentalAccess access;
        try {
            access = rentalAccesses.saveAndFlush(new RentalAccess(accountId, rentalId, now));
        } catch (DataIntegrityViolationException e) {
            // 같은 렌탈을 다른 고객이 동시에 연결했다(rental_id UNIQUE). 트랜잭션째 되돌려 링크도 다시 쓸 수 있게 둔다
            throw new AuthException(ErrorCode.RENTAL_LINKED_TO_OTHER);
        }
        // 연결 전에 봉인된 기록(보통 출고)의 영수증을 이제 보낸다(FR-INT-03). 메일은 커밋 뒤에 나간다
        receipts.onRentalLinked(access);
    }

    public record IssuedLink(String url, Instant expiresAt) {
    }

    public record CaptureToken(IssuedToken token, String rentalId, String checkpointId) {
    }
}
