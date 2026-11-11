package com.gakdo.trace.auth.account.domain;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Lock;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import jakarta.persistence.LockModeType;

public interface AccountRepository extends JpaRepository<Account, Long> {

    Optional<Account> findByEmail(String email);

    /** 계정 행을 잠그고 읽는다. 재설정 코드 하루 상한 검사·발급을 계정마다 한 번에 하나씩 하려고 쓴다. */
    @Lock(LockModeType.PESSIMISTIC_WRITE)
    @Query("select a from Account a where a.email = :email")
    Optional<Account> findByEmailForUpdate(@Param("email") String email);

    boolean existsByEmail(String email);

    Optional<Account> findByPublicId(String publicId);
}
