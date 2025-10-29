package com.bookify.auth_service.authn.admin.oauth.dto;

import lombok.Data;

@Data
public class TokenSettingsDTO {
    private Long accessTokenTimeToLive;     // seconds
    private Long refreshTokenTimeToLive;    // seconds
    private boolean reuseRefreshTokens;     // true/false

}
