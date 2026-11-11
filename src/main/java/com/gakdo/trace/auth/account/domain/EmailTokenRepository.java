package com.gakdo.trace.auth.account.domain;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;

import jakarta.persistence.LockModeType;

public interface EmailTokenRepository extends JpaRepository<EmailToken, Long> {

    /**
     * 가장 최근에 만든 아직 안 쓴 코드. 새 코드를 만들면 앞 코드는 폐기되므로 하나뿐이다.
     * 동시에 확인해도 틀린 횟수가 덮어써지지 않게 행을 잠근다(CWE-307).
     */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    Optional<EmailToken> findFirstByAccountIdAndPurposeAndUsedAtIsNullOrderByCreatedAtDescIdDesc(
            Long accountId, EmailTokenPurpose purpose);

    List<EmailToken> findByAccountIdAndPurposeAndUsedAtIsNull(Long accountId, EmailTokenPurpose purpose);

    /** 그 계정·용도로 since 뒤에 만든 코드 수(쓴 것·폐기한 것 포함). 재설정 코드 발급 횟수 상한에 쓴다. */
    long countByAccountIdAndPurposeAndCreatedAtAfter(Long accountId, EmailTokenPurpose purpose, Instant since);
}
