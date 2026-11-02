package com.gakdo.trace.auth.account.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface RentalAccessRepository extends JpaRepository<RentalAccess, Long> {

    List<RentalAccess> findByAccountIdOrderByLinkedAtAsc(Long accountId);

    Optional<RentalAccess> findByRentalId(String rentalId);
}
