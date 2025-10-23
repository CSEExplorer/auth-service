package com.bookify.auth_service.authn.user.dto;


import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class BasicAuthResponse {
    private String token;
    private String message;
    private String username;
}

