package com.gakdo.trace.auth.account.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface EmailTokenRepository extends JpaRepository<EmailToken, Long> {

    /** 가장 최근에 만든 아직 안 쓴 코드. 새 코드를 만들면 앞 코드는 폐기되므로 하나뿐이다. */
    Optional<EmailToken> findFirstByAccountIdAndPurposeAndUsedAtIsNullOrderByCreatedAtDescIdDesc(
            Long accountId, EmailTokenPurpose purpose);

    List<EmailToken> findByAccountIdAndPurposeAndUsedAtIsNull(Long accountId, EmailTokenPurpose purpose);
}
