package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class ProviderMismatchException extends AuthException {
    public ProviderMismatchException() {
        super(
                "AUTH_PROVIDER_MISMATCH",
                "This account uses a different login method",
                HttpStatus.BAD_REQUEST
        );
    }
}

