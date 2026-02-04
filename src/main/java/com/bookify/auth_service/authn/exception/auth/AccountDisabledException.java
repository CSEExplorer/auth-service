package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class AccountDisabledException extends AuthException {
    public AccountDisabledException() {
        super(
                "AUTH_ACCOUNT_DISABLED",
                "Account is disabled",
                HttpStatus.FORBIDDEN
        );
    }
}

