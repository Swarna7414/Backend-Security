package com.DenitMap.DMB_Security.DTO;

import lombok.Data;

@Data
public class ForgotPasswordRequest {
    private String email;

    private String otp;

    private String password;

    private String newPassword;
}