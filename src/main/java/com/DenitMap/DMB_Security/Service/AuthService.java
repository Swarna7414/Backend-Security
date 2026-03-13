package com.DenitMap.DMB_Security.Service;

import com.DenitMap.DMB_Security.DTO.*;
import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.*;
import com.DenitMap.DMB_Security.Repository.AuthAccountRepository;
import com.DenitMap.DMB_Security.Repository.RefreshTokenRepository;
import com.DenitMap.DMB_Security.Repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final AuthAccountRepository authAccountRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final OtpService otpService;

    private final EmailService emailService;

    private final JwtService jwtService;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpMs;

    public APIResponse signUpLocal(SignupRequest signupRequest, String otp){
        if (!signupRequest.getPassword().equals(signupRequest.getConfirmPassword())){
            log.error("Conform Password Doesn't Match with the Orginal Password");
            throw new BadRequestException("Password's didn't Match");
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())){
            log.error("Email was already present in the DataBase");
            throw new BadRequestException("Email already found in the DB please use Different Mail");
        }

        otpService.validateOrThrow(signupRequest.getEmail(), otp, OtpPurpose.SIGN_UP);

        log.info("OTP Validation Completed");

        User user = User.builder().firstName(signupRequest.getFirstName()).lastName(signupRequest.getLastName())
                .gender(signupRequest.getGender()).dateOfBirth(signupRequest.getDateOfBirth()).email(signupRequest.getEmail())
                .createdAt(Instant.now()).build();

        log.info("User Loaded");

        userRepository.save(user);

        log.info("User Saved to the DataBase {}", user.getEmail());


        log.info("Saved details to the Auth Account");
        AuthAccount authAccount = AuthAccount.builder().user(user).provider(AuthProvider.LOCAL).providerUserId(null)
                .passwordHash(passwordEncoder.encode(signupRequest.getPassword())).createdAt(Instant.now()).build();

        authAccountRepository.save(authAccount);
        log.info("Saved the Auth Account");

        emailService.sendMail(user.getEmail(), "Welcome to DMB Security !", "Your account has been Successfully Created");
        log.info("Mail sent to the User");

        return new APIResponse("Account Successfully Created, Please Login");
    }

    public AuthResponse loginLocal(LoginRequest loginRequest){

        User user = userRepository.findByEmail(loginRequest.getEmail()).orElseThrow(()->new BadRequestException("User Not found in the Db please Signup"));

        log.info("This is the User {}", user.getEmail());
        AuthAccount local = authAccountRepository.findByUserIdAndProvider(user.getId(), AuthProvider.LOCAL).orElseThrow(
                ()-> new BadRequestException("This Email uses Google Login please use the Google Login")
        );

        if (loginRequest.getPassword() == null || !passwordEncoder.matches(loginRequest.getPassword(), local.getPasswordHash())){
            throw new BadRequestException("Invalid Password");
        }

        String access = jwtService.generateJWTToken(user);
        String refresh = jwtService.generateRefreshToken(user);

        log.info("Generated The Tokens");

        saveRefresh(user, refresh);

        log.info("Saved the Generated tokens");

        return new AuthResponse(access, refresh);
    }

    public APIResponse forgotPasswordLocal(ForgotPasswordRequest forgotPasswordRequest){

        User user = userRepository.findByEmail(forgotPasswordRequest.getEmail()).orElseThrow(
                ()-> new BadRequestException("User was not Found in the Database, please Signup Again")
        );

        AuthAccount authAccount = authAccountRepository.findByUserIdAndProvider(user.getId(),AuthProvider.LOCAL)
                        .orElseThrow(()-> new BadRequestException(" User Not Found in the DataBase"));

        log.info("User and Auth Accounts was loaded");


        otpService.validateOrThrow(forgotPasswordRequest.getEmail(), forgotPasswordRequest.getOtp(), OtpPurpose.FORGOT_PASSWORD);

        log.info("OTP Validated");

        if (!forgotPasswordRequest.getNewPassword().equals(forgotPasswordRequest.getConfirmNewPassword())){
            log.error("Password Doesn't Match");
            throw new BadRequestException("Password Doesn't Match");
        }


        authAccount.setPasswordHash(passwordEncoder.encode(forgotPasswordRequest.getNewPassword()));

        log.info("Password successfully Changed");

        authAccountRepository.save(authAccount);

        return new APIResponse("Password Reseted Successfully completed");

    }

    public AuthResponse refreshRequest(RefreshRequest refreshRequest){
        RefreshToken refreshToken = refreshTokenRepository.findByToken(refreshRequest.getRefreshToken()).orElseThrow(
                ()-> new BadRequestException("Refresh Token was not found in the DataBase")
        );

        Claims claims = jwtService.validateAndGetClaims(refreshToken.getToken());
        if (!"refresh".equalsIgnoreCase(String.valueOf(claims.get("type")))){
            throw new BadRequestException("Invalid RefreshToken Type");
        }

        User user = refreshToken.getUser();

        refreshTokenRepository.delete(refreshToken);

        String newAccess = jwtService.generateJWTToken(user);
        String newRefresh = jwtService.generateRefreshToken(user);

        saveRefresh(user, newRefresh);

        return new AuthResponse(newAccess, newRefresh);
    }

    public APIResponse logout(RefreshRequest refreshRequest){
        refreshTokenRepository.deleteByToken(refreshRequest.getRefreshToken());
        return new APIResponse("Loged out Successfully !");
    }

    public void saveRefresh(User user, String refresh) {
        RefreshToken refreshToken = RefreshToken.builder().token(refresh).expiresAt(Instant.now()).user(user).build();
        refreshTokenRepository.save(refreshToken);
    }

}