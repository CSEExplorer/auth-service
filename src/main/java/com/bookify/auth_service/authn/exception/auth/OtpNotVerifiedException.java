package com.bookify.auth_service.authn.exception.auth;

import org.springframework.http.HttpStatus;

public class OtpNotVerifiedException extends AuthException {
    public OtpNotVerifiedException() {
        super(
                "AUTH_OTP_NOT_VERIFIED",
                "OTP verification required",
                HttpStatus.FORBIDDEN
        );
    }
}
