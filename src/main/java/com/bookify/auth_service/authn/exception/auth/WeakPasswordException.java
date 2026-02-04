package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class WeakPasswordException extends AuthException {
    public WeakPasswordException() {
        super(
                "AUTH_WEAK_PASSWORD",
                "Password does not meet security requirements",
                HttpStatus.BAD_REQUEST
        );
    }
}
