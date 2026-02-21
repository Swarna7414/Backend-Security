package com.DenitMap.DMB_Security.DTO;

import jakarta.validation.constraints.NotBlank;
import lombok.Data;

@Data
public class RefreshRequest {

    @NotBlank
    private String refreshToken;
}
