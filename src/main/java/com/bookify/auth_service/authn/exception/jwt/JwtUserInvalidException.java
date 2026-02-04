package com.bookify.auth_service.authn.exception.jwt;

import org.springframework.http.HttpStatus;

public class JwtUserInvalidException extends JwtAuthException {

    public JwtUserInvalidException() {
        super(
                "AUTH_USER_INVALID",
                "User associated with token is no longer valid",
                HttpStatus.UNAUTHORIZED
        );
    }
}
