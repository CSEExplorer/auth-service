package com.bookify.auth_service.authn.user.oauth.external.dto;


import lombok.Data;

@Data
public class OAuthTokenResponseDto {
    private String accessToken;
    private String tokenType = "Bearer";
    private Long expiresIn;  // seconds
    private String refreshToken; // optional
    private String provider; // e.g., "google"
}

