package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class OtpAttemptsExceededException extends AuthException {
    public OtpAttemptsExceededException() {
        super(
                "AUTH_OTP_ATTEMPTS_EXCEEDED",
                "OTP attempts exceeded",
                HttpStatus.TOO_MANY_REQUESTS
        );
    }
}

