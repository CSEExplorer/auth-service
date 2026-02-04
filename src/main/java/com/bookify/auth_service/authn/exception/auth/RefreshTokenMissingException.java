package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class RefreshTokenMissingException extends AuthException {
    public RefreshTokenMissingException() {
        super(
                "AUTH_REFRESH_TOKEN_MISSING",
                "Refresh token is missing",
                HttpStatus.UNAUTHORIZED
        );
    }
}

