package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class UserNotFoundException extends AuthException {
    public UserNotFoundException() {
        super(
                "AUTH_USER_NOT_FOUND",
                "User does not exist",
                HttpStatus.UNAUTHORIZED
        );
    }
}

