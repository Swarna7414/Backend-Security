package com.DenitMap.DMB_Security.Service;

import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.OTPToken;
import com.DenitMap.DMB_Security.Model.Purpose;
import com.DenitMap.DMB_Security.Repository.OtpRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Random;

@Service
@RequiredArgsConstructor
public class OtpService {

    private final OtpRepository otpRepository;

    private final PasswordEncoder passwordEncoder;

    private final EmailService emailService;

    private static final long OTP_EXPIRATION_MS = 5*60*1000;

    public void generateOtpAndSend(String mail, Purpose purpose){
        String otp = String.format("%06d",new Random().nextInt(999999));
        otpRepository.deleteByEmailAndPurpose(mail, purpose);

        OTPToken otpToken = OTPToken.builder().email(mail).otp(passwordEncoder.encode(otp)).purpose(purpose)
                .expiresAt(Instant.now().plusMillis(OTP_EXPIRATION_MS)).build();

        otpRepository.save(otpToken);

        emailService.sendMail(mail,otp);
    }

    public boolean validateSentOtp(String email, String otp, Purpose purpose){

        OTPToken otpToken = otpRepository.findByEmailAndPurpose(email, purpose)
                .orElseThrow(()-> new BadRequestException("Something went Wrong Please try again later"));
        if (otpToken.getExpiresAt().isBefore(Instant.now())){
            throw new BadRequestException("Invalid OTP, OTP already Expired");
        }

        if (!passwordEncoder.matches(otp, otpToken.getOtp())){
            throw new BadRequestException("OTP Doesn't Match");
        }

        if(!passwordEncoder.matches(otp, otpToken.getOtp())){
            return false;
        }

        otpRepository.delete(otpToken);

        return true;

    }
}