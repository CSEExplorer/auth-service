package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenSignatureException extends JwtAuthException {

    public JwtTokenSignatureException() {
        super(
                "AUTH_ACCESS_TOKEN_SIGNATURE_INVALID",
                "JWT signature is invalid",
                HttpStatus.UNAUTHORIZED
        );
    }
}
