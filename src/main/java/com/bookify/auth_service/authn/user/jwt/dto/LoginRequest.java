package com.bookify.auth_service.authn.user.jwt.dto;

import com.bookify.auth_service.authn.validation.ValidPassword;
import lombok.Data;


import jakarta.validation.constraints.NotBlank;

@Data
public class LoginRequest {

    @NotBlank(message = "Username or email is required")
    private String usernameOrEmail;

    @NotBlank(message = "Password is required")
    @ValidPassword
    private String password;
}
