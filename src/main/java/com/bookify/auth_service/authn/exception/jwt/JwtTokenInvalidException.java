package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenInvalidException extends JwtAuthException {

    public JwtTokenInvalidException() {
        super(
                "AUTH_ACCESS_TOKEN_INVALID",
                "Access token is invalid",
                HttpStatus.UNAUTHORIZED
        );
    }
}
