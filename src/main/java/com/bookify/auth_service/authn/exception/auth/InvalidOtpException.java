package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class InvalidOtpException extends AuthException {
    public InvalidOtpException() {
        super(
                "AUTH_OTP_INVALID",
                "Invalid OTP",
                HttpStatus.BAD_REQUEST
        );
    }
}

