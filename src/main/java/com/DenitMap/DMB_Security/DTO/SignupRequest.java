package com.DenitMap.DMB_Security.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.Data;

import java.time.LocalDate;

@Data
public class SignupRequest {

    @NotBlank
    private String firstName;

    @NotBlank
    private String lastName;

    @NotBlank
    private String gender;

    @NotNull(message = "Date of Birth is Required")
    private LocalDate dateOfBirth;

    @NotBlank
    @Email
    private String email;

    @NotBlank
    @Size(min = 8, message = "password must be atleast 8 charachers")
    private String password;

    @NotBlank
    private String confirmPassword;

}