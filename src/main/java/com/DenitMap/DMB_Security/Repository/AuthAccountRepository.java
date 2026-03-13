package com.DenitMap.DMB_Security.Repository;

import com.DenitMap.DMB_Security.Model.AuthAccount;
import com.DenitMap.DMB_Security.Model.AuthProvider;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface AuthAccountRepository extends JpaRepository<AuthAccount, String> {
    Optional<AuthAccount> findByUserIdAndProvider(String userId, AuthProvider provider);
    Optional<AuthAccount> findByProviderAndProviderUserId(AuthProvider provider, String providerUserId);
}
