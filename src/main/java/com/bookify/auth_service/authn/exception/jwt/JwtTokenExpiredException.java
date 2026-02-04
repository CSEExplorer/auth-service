package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenExpiredException extends JwtAuthException {

    public JwtTokenExpiredException() {
        super(
                "AUTH_ACCESS_TOKEN_EXPIRED",
                "Access token has expired",
                HttpStatus.UNAUTHORIZED
        );
    }
}
