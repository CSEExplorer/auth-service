package com.bookify.auth_service.authn.user.jwt.dto;



import com.bookify.auth_service.authn.validation.ValidPassword;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;


@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Username cannot be empty")
    private String username;

    @Email(message = "Invalid email format")
    @NotBlank(message = "Email cannot be empty")
    private String email;

    @NotBlank(message = "Password cannot be empty")
    @ValidPassword
    private String password;

    private String role;
}
