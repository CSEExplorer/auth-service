package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenRevokedException extends JwtAuthException {

    public JwtTokenRevokedException() {
        super(
                "AUTH_ACCESS_TOKEN_REVOKED",
                "Access token has been revoked",
                HttpStatus.UNAUTHORIZED
        );
    }
}
