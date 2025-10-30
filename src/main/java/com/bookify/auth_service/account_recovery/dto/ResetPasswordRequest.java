package com.bookify.auth_service.account_recovery.dto;


import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

public record ResetPasswordRequest(
        @NotBlank String token,
        @NotBlank @Size(min = 8, max = 64)
        String newPassword
) {}

