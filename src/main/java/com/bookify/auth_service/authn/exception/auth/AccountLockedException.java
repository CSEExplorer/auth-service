package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class AccountLockedException extends AuthException {
    public AccountLockedException() {
        super(
                "AUTH_ACCOUNT_LOCKED",
                "Account is locked due to multiple failed attempts",
                HttpStatus.LOCKED
        );
    }
}

