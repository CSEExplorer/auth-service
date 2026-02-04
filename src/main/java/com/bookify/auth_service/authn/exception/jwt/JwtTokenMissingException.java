package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenMissingException extends JwtAuthException {

    public JwtTokenMissingException() {
        super(
                "AUTH_ACCESS_TOKEN_MISSING",
                "Access token is missing",
                HttpStatus.UNAUTHORIZED
        );
    }
}
