package com.gakdo.trace.auth.account.application;

import java.time.Clock;
import java.time.Instant;

import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import com.gakdo.trace.auth.account.domain.Account;
import com.gakdo.trace.auth.account.domain.EmailToken;
import com.gakdo.trace.auth.account.domain.EmailTokenPurpose;
import com.gakdo.trace.auth.account.domain.EmailTokenRepository;
import com.gakdo.trace.auth.common.domain.AuthException;
import com.gakdo.trace.auth.common.domain.CodeInvalidException;
import com.gakdo.trace.auth.common.domain.ErrorCode;
import com.gakdo.trace.auth.common.infra.SecureTokens;
import com.gakdo.trace.auth.common.infra.Sha256;
import com.gakdo.trace.auth.config.EmailCodeProperties;

/**
 * 6자리 메일 코드 발급·확인(설계서 "이메일 인증·비밀번호 재설정").
 * 새 코드를 만들면 같은 용도의 앞 코드는 폐기한다. 메일은 DB 커밋 뒤에 보낸다(롤백된 코드를 보내지 않게).
 * 호출하는 쪽 트랜잭션 안에서 쓴다.
 */
@Component
public class EmailCodeService {

    private final EmailTokenRepository tokens;
    private final SecureTokens secureTokens;
    private final CodeMailer mailer;
    private final EmailCodeProperties properties;
    private final Clock clock;

    public EmailCodeService(EmailTokenRepository tokens, SecureTokens secureTokens, CodeMailer mailer,
                            EmailCodeProperties properties, Clock clock) {
        this.tokens = tokens;
        this.secureTokens = secureTokens;
        this.mailer = mailer;
        this.properties = properties;
        this.clock = clock;
    }

    public void issue(Account account, EmailTokenPurpose purpose) {
        Instant now = clock.instant();
        tokens.findByAccountIdAndPurposeAndUsedAtIsNull(account.getId(), purpose)
                .forEach(old -> old.markUsed(now));
        String code = secureTokens.sixDigitCode();
        tokens.save(EmailToken.issue(account.getId(), purpose, Sha256.hex(code), now.plus(properties.ttl()), now));
        String to = account.getEmail();
        afterCommit(() -> mailer.send(to, purpose, code));
    }

    /**
     * 코드가 맞으면 쓰인 것으로 표시한다. 없거나 만료·폐기면 410 CODE_EXPIRED, 틀리면 400 CODE_INVALID(남은 횟수).
     * 틀린 횟수가 남도록 호출하는 쪽은 CodeInvalidException에 롤백하지 않는다.
     */
    public void consume(Account account, EmailTokenPurpose purpose, String code) {
        Instant now = clock.instant();
        EmailToken token = tokens.findFirstByAccountIdAndPurposeAndUsedAtIsNullOrderByCreatedAtDescIdDesc(
                        account.getId(), purpose)
                .filter(t -> t.usable(now))
                .orElseThrow(() -> new AuthException(ErrorCode.CODE_EXPIRED));
        if (!Sha256.hex(code).equals(token.getCodeHash())) {
            throw new CodeInvalidException(token.recordFailure(properties.maxAttempts(), now));
        }
        token.markUsed(now);
    }

    private static void afterCommit(Runnable action) {
        if (TransactionSynchronizationManager.isSynchronizationActive()) {
            TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
                @Override
                public void afterCommit() {
                    action.run();
                }
            });
        } else {
            action.run();
        }
    }
}
