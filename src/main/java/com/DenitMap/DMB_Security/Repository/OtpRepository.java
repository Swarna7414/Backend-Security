package com.DenitMap.DMB_Security.Repository;

import com.DenitMap.DMB_Security.Model.OTPToken;
import com.DenitMap.DMB_Security.Model.Purpose;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

public interface OtpRepository extends JpaRepository<OTPToken, String> {
    Optional<OTPToken> findByEmailAndPurpose(String email, Purpose purpose);

    @Transactional
    void deleteByEmailAndPurpose(String email, Purpose purpose);
}
