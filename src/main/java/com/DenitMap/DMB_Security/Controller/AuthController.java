package com.DenitMap.DMB_Security.Controller;


import com.DenitMap.DMB_Security.DTO.*;
import com.DenitMap.DMB_Security.Service.AuthService;
import com.DenitMap.DMB_Security.Service.OtpService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    private final OtpService otpService;

    @PostMapping("/send-otp")
    public ResponseEntity<APIResponse> sendOtp(@Valid @RequestBody SendOtpRequest sendOtpRequest){
        otpService.generateOtpAndSend(sendOtpRequest.getEmail(), sendOtpRequest.getOtpPurpose());
        return ResponseEntity.ok().body(new APIResponse("OTP sent Successfully please Signup using OTP"));
    }

    @PostMapping("/signup")
    public ResponseEntity<APIResponse> signUp(@RequestBody SignupRequest signupRequest, @RequestParam String otp){
        return ResponseEntity.ok().body(authService.signUpLocal(signupRequest, otp));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@Valid @RequestBody LoginRequest loginRequest){
        return ResponseEntity.ok().body(authService.loginLocal(loginRequest));
    }

    @PostMapping("forgot-password")
    public ResponseEntity<APIResponse> forgotPassword(@RequestBody ForgotPasswordRequest forgotPasswordRequest){
        return ResponseEntity.ok(authService.forgotPasswordLocal(forgotPasswordRequest));
    }

    @PostMapping("/refresh")
    public ResponseEntity<AuthResponse> refresh(@RequestBody RefreshRequest refreshRequest){
        return ResponseEntity.ok(authService.refreshRequest(refreshRequest));
    }

    @PostMapping("/logout")
    public ResponseEntity<APIResponse> logout(@RequestBody RefreshRequest refreshRequest){
        return ResponseEntity.ok().body(authService.logout(refreshRequest));
    }

}