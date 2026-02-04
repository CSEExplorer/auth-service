package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtTokenClaimsInvalidException extends JwtAuthException {

    public JwtTokenClaimsInvalidException() {
        super(
                "AUTH_ACCESS_TOKEN_CLAIMS_INVALID",
                "JWT claims are missing or invalid",
                HttpStatus.UNAUTHORIZED
        );
    }
}
