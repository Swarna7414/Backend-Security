package com.DenitMap.DMB_Security.Service;

import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.OtpPurpose;
import com.DenitMap.DMB_Security.Model.OtpToken;
import com.DenitMap.DMB_Security.Repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Random;

@Slf4j
@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;

    private final PasswordEncoder passwordEncoder;

    private final EmailService emailService;

    private static final long OTP_EXP_MS = 5*60*1000;

    public void generateOtpAndSend(String email, OtpPurpose otpPurpose){
        String otp = String.format("%06d", new Random().nextInt(1_000_000));

        log.info("OTP Generated {}",otp);
        otpRepository.deleteByEmailAndPurpose(email, otpPurpose);

        log.info("Deleted the OTP in the Otp repository {}", email);
        OtpToken otpToken = OtpToken.builder().email(email).otpPurpose(otpPurpose).otpHash(passwordEncoder.encode(otp))
                .expiresAt(Instant.now().plusMillis(OTP_EXP_MS)).build();

        otpRepository.save(otpToken);

        log.info("saved the New OTP token to the Repository");

        String body = "Hey this your OTP"+otp+"for"+otpPurpose.name()+"& this will expire in 5 minutes";

        emailService.sendMail(email, "Your OTP Code for"+otpPurpose.name(), body);

        log.info("Mail sent to the {}", email);
    }

    public void validateOrThrow(String email, String otp, OtpPurpose otpPurpose){
        OtpToken otpToken = otpRepository.findByEmailAndPurpose(email, otpPurpose)
                .orElseThrow(()->new BadRequestException("Otp not found in the DataBase, Please Request again"));

        log.info("Got the OtpToken from the Repository {} ", otpToken);
        if (otpToken.getExpiresAt().isBefore(Instant.now())){
            log.error("OPT was expired");
            throw new BadRequestException("OTP Expired please try again");
        }

        if (!passwordEncoder.matches(otpToken.getOtpHash(), otp)){
            log.error("Password wasn't Matching");
            throw new BadRequestException("OTP isn't matching");
        }

        otpRepository.delete(otpToken);
        log.info("OTP was successfully Deleted");
    }


}