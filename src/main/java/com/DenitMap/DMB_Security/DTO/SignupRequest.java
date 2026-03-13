package com.DenitMap.DMB_Security.DTO;


import jakarta.validation.constraints.*;
import lombok.Data;

import java.time.LocalDate;

@Data
public class SignupRequest {

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    private String gender;

    @NotNull
    private LocalDate dateOfBirth;

    @NotBlank
    @Size(min = 8, message = "password must not be at least 8 characters")
    @Pattern(regexp = "^(?=.*[A-Z])(?=.*\\\\d).{8,}$", message = "Password must be at least 8 characters long, contain one uppercase letter and one number")
    private String password;

    @NotBlank
    private String confirmPassword;
}