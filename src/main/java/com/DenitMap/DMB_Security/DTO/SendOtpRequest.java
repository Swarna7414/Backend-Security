package com.DenitMap.DMB_Security.DTO;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import com.DenitMap.DMB_Security.Model.Purpose;
import lombok.Data;

@Data
public class SendOtpRequest {

    @NotBlank
    @Email
    private String email;

    @NotNull
    private Purpose purpose;
}
