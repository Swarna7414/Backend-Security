package com.DenitMap.DMB_Security.Service;

import com.DenitMap.DMB_Security.DTO.*;
import com.DenitMap.DMB_Security.Exceptions.BadRequestException;
import com.DenitMap.DMB_Security.Model.RefreshToken;
import com.DenitMap.DMB_Security.Model.User;
import com.DenitMap.DMB_Security.Repository.RefreshTokenRepository;
import com.DenitMap.DMB_Security.Repository.UserRepository;
import io.jsonwebtoken.Claims;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
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

    @Autowired
    private final JwtService jwtService;

    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpMs;

    public ApiResponse signup(SignupRequest signupRequest){
        if (!signupRequest.getPassword().equals(signupRequest.getConfirmPassword())){
            throw new BadRequestException("Password is Not Matching");
        }
        if (userRepository.existsByEmail(signupRequest.getEmail())){
            throw new BadRequestException("User with Same Mail already exist");
        }

        User user = User.builder().firstName(signupRequest.getFirstName()).lastName(signupRequest.getLastName())
                .gender(signupRequest.getGender()).dateOfBirth(signupRequest.getDateOfBirth())
                .dateOfBirth(signupRequest.getDateOfBirth()).email(signupRequest.getEmail()).passwordHash(passwordEncoder.encode(signupRequest.getPassword()))
                .build();


        userRepository.save(user);

        ApiResponse apiResponse = new ApiResponse("User Sussessfully Registered");

        return apiResponse;
    }


    public AuthResponse login(LoginRequest loginRequest){
        User user = userRepository.findByEmail(loginRequest.getEmail())
                .orElseThrow(()-> new BadRequestException("email address not found in the Database"));

        if (!passwordEncoder.matches(loginRequest.getPassword(), user.getPasswordHash())){
            throw new BadRequestException("Invalid Password");
        }

        String access = jwtService.generateToken(user);
        String refresh = jwtService.generateRefreshToken(user);

        saveRefresh(user,refresh);

        return new AuthResponse(access, refresh);

    }

    public AuthResponse refresh(RefreshRequest refreshRequest){
        RefreshToken oldToken = refreshTokenRepository.findByToken(refreshRequest.getRefreshToken())
                .orElseThrow(()-> new BadRequestException("Invalid Refresh token Please try to Refresh again"));

        if (oldToken.getExpiresAt().isBefore(Instant.now())){
            refreshTokenRepository.delete(oldToken);
            throw new BadRequestException("Please login in again using Credentials");
        }

        Claims claims = jwtService.validateAndGetClaims(oldToken.getToken());
        Object type = claims.get("type");
        if (type == null || !"refresh".equals(type.toString())){
            throw new BadRequestException("Invalid Refresh token type");
        }

        User user = oldToken.getUser();

        refreshTokenRepository.delete(oldToken);

        String newAccess = jwtService.generateToken(user);
        String newRefreshToken = jwtService.generateRefreshToken(user);
        saveRefresh(user, newRefreshToken);

        return new AuthResponse(newAccess, newRefreshToken);
    }

    public ApiResponse logout(RefreshRequest refreshRequest){
        refreshTokenRepository.deleteByToken(refreshRequest.getRefreshToken());
        return new ApiResponse("Logged out Sucessfully");
    }

    private void saveRefresh(User user, String refresh) {
        RefreshToken refreshToken = RefreshToken.builder().user(user).token(refresh).expiresAt(Instant.now().plusMillis(refreshExpMs))
                .build();

        refreshTokenRepository.save(refreshToken);
    }
}