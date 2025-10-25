package com.bookify.auth_service.authn.user.oauth.external.dto;

import lombok.Data;

@Data
public class OAuthCallbackRequestDto {
    private String code;
    private String state; // Optional if you implement CSRF protection
}

