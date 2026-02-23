package com.DenitMap.DMB_Security.Service;

import com.DenitMap.DMB_Security.DTO.*;
import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.Purpose;
import com.DenitMap.DMB_Security.Model.RefreshToken;
import com.DenitMap.DMB_Security.Model.User;
import com.DenitMap.DMB_Security.Repository.RefreshTokenRepository;
import com.DenitMap.DMB_Security.Repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Instant;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;

    private final RefreshTokenRepository refreshTokenRepository;

    private final PasswordEncoder passwordEncoder;

    private final OtpService otpService;

    private final EmailService emailService;

    private final JwtService jwtService;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpMs;

    public ApiResponse signup(SignupRequest signupRequest, String otp) {

        if (!signupRequest.getPassword().equals(signupRequest.getConfirmPassword())) {
            throw new BadRequestException("Password Doesn't Match");
        }

        if (userRepository.existsByEmail(signupRequest.getEmail())) {
            throw new BadRequestException("Email already registered");
        }

        boolean isVerified = otpService.validateSentOtp(signupRequest.getEmail(), otp, Purpose.SIGN_UP);

        if (!isVerified) {
            throw new BadRequestException("OTP verification failed");
        }

        User user = User.builder().firstName(signupRequest.getFirstName()).lastName(signupRequest.getLastName())
                .gender(signupRequest.getGender()).dateOfBirth(signupRequest.getDateOfBirth())
                .email(signupRequest.getEmail())
                .passwordHash(passwordEncoder.encode(signupRequest.getPassword())).build();

        userRepository.save(user);

        emailService.sendMail(signupRequest.getEmail(), "Welcome to DMB Security!",
                "Your account has been successfully created.");

        return new ApiResponse("Signup successful! Please login.");
    }

    public AuthResponse login(LoginRequest loginRequest) {

        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(() -> new BadRequestException("email address not found in the Database"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())) {
            throw new BadRequestException("Invalid Password");
        }

        String access = jwtService.generateToken(user);
        String refresh = jwtService.generateRefreshToken(user);

        saveRefresh(user, refresh);

        return new AuthResponse(access, refresh);
    }

    public ApiResponse requestForForgotPassword(ForgotPasswordRequest forgotPasswordRequest) {
        if (!userRepository.existsByEmail(forgotPasswordRequest.getEmail())) {
            throw new BadRequestException("Email was not found in the repository. Please sign up.");
        }

        boolean isValid = otpService.validateSentOtp(forgotPasswordRequest.getEmail(), forgotPasswordRequest.getOtp(),
                Purpose.FORGOT_PASSWORD);

        if (!isValid) {
            throw new BadRequestException("Something went wrong. Please try again later.");
        }

        if (!forgotPasswordRequest.getPassword().equals(forgotPasswordRequest.getNewPassword())) {
            throw new BadRequestException("Passwords do not match.");
        }

        User user = userRepository.findByEmail(forgotPasswordRequest.getEmail())
                .orElseThrow(() -> new BadRequestException("User was not found."));

        user.setPasswordHash(passwordEncoder.encode(forgotPasswordRequest.getPassword()));
        userRepository.save(user);

        return new ApiResponse("Password successfully reset.");
    }

    public ApiResponse CheckResetPassword(ForgotPasswordRequest forgotPasswordRequest) {

        if (!userRepository.existsByEmail(forgotPasswordRequest.getEmail())) {
            throw new BadRequestException("Email Not Found in the DB");
        }

        boolean isVerified = otpService.validateSentOtp(forgotPasswordRequest.getEmail(),
                forgotPasswordRequest.getOtp(), Purpose.FORGOT_PASSWORD);

        if (!isVerified) {
            throw new BadRequestException("Please try again later");
        }

        return new ApiResponse("Password reset  Successfully Completed");

    }

    public AuthResponse refresh(RefreshRequest refreshRequest) {
        RefreshToken oldToken = refreshTokenRepository.findByToken(refreshRequest.getRefreshToken())
                .orElseThrow(() -> new BadRequestException("Invalid Refresh token Please try to Refresh again"));

        if (oldToken.getExpiresAt().isBefore(Instant.now())) {
            refreshTokenRepository.delete(oldToken);
            throw new BadRequestException("Please login in again using Credentials");
        }

        Claims claims = jwtService.validateAndGetClaims(oldToken.getToken());
        Object type = claims.get("type");
        if (type == null || !"refresh".equals(type.toString())) {
            throw new BadRequestException("Invalid Refresh token type");
        }

        User user = oldToken.getUser();

        refreshTokenRepository.delete(oldToken);

        String newAccess = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);
        saveRefresh(user, newRefreshToken);

        return new AuthResponse(newAccess, newRefreshToken);
    }

    public ApiResponse logout(RefreshRequest refreshRequest) {
        refreshTokenRepository.deleteByToken(refreshRequest.getRefreshToken());
        return new ApiResponse("Logged out Sucessfully");
    }

    private void saveRefresh(User user, String refresh) {

        RefreshToken refreshToken = RefreshToken.builder().user(user).token(refresh)
                .expiresAt(Instant.now().plusMillis(refreshExpMs))
                .build();

        refreshTokenRepository.save(refreshToken);
    }
}