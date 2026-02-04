package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class OtpExpiredException extends AuthException {
    public OtpExpiredException() {
        super(
                "AUTH_OTP_EXPIRED",
                "OTP has expired",
                HttpStatus.BAD_REQUEST
        );
    }
}

