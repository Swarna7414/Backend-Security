package com.DenitMap.DMB_Security.Repository;

import com.DenitMap.DMB_Security.Model.OtpPurpose;
import com.DenitMap.DMB_Security.Model.OtpToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<OtpToken, String> {
    Optional<OtpToken> findByEmailAndPurpose(String email, OtpPurpose otpPurpose);

    @Transactional
    void deleteByEmailAndPurpose(String email, OtpPurpose otpPurpose);
}
