package com.DenitMap.DMB_Security.Controller;


import com.DenitMap.DMB_Security.DTO.*;
import com.DenitMap.DMB_Security.Service.AuthService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    @Autowired
    private final AuthService authService;

    @PostMapping("/signup")
    public ResponseEntity<ApiResponse> signup(@RequestBody SignupRequest signupRequest, @RequestParam String otp){
        return ResponseEntity.ok(authService.signup(signupRequest, otp));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok().body(authService.login(loginRequest));
    }

    @PostMapping("/forgotpassword")
    public ResponseEntity<ApiResponse> forgotPassword(ForgotPasswordRequest forgotPasswordRequest){
        return ResponseEntity.ok(authService.requestForForgotPassword(forgotPasswordRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refreshRequest(@Valid @RequestBody RefreshRequest refreshRequest){
        return ResponseEntity.ok().body(authService.refresh(refreshRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse> logout(@Valid @RequestBody RefreshRequest refreshRequest){
        return ResponseEntity.ok().body(authService.logout(refreshRequest));
    }

}