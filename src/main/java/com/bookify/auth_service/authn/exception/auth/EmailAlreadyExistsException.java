package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class EmailAlreadyExistsException extends AuthException {
    public EmailAlreadyExistsException() {
        super(
                "AUTH_EMAIL_ALREADY_EXISTS",
                "Email already registered",
                HttpStatus.CONFLICT
        );
    }
}
