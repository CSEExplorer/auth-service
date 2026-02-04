package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class InvalidCredentialsException extends AuthException {
    public InvalidCredentialsException() {
        super(
                "AUTH_INVALID_CREDENTIALS",
                "Email or password is incorrect",
                HttpStatus.UNAUTHORIZED
        );
    }
}

