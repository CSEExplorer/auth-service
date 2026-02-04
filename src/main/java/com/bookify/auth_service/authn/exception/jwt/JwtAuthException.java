package com.bookify.auth_service.authn.exception.jwt;

import com.bookify.auth_service.authn.exception.auth.AuthException;
import org.springframework.http.HttpStatus;

public abstract class JwtAuthException extends AuthException {

    protected JwtAuthException(String code, String message, HttpStatus status) {
        super(code, message, status);
    }
}

