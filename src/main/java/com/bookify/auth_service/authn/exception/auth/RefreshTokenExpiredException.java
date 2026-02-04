package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class RefreshTokenExpiredException extends AuthException {
    public RefreshTokenExpiredException() {
        super(
                "AUTH_REFRESH_TOKEN_EXPIRED",
                "Refresh token has expired",
                HttpStatus.UNAUTHORIZED
        );
    }
}

