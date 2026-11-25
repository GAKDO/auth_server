package com.gakdo.trace.auth.social.domain;

import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

public interface SocialIdentityRepository extends JpaRepository<SocialIdentity, Long> {

    Optional<SocialIdentity> findByProviderAndSubject(SocialProvider provider, String subject);

    Optional<SocialIdentity> findByAccountIdAndProvider(Long accountId, SocialProvider provider);

    List<SocialIdentity> findByAccountId(Long accountId);

    void deleteByAccountId(Long accountId);
}
