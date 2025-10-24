package com.bookify.auth_service.authn.exception.jwt;

public class JwtTokenRevokedException extends RuntimeException {
    public JwtTokenRevokedException(String message) {
        super(message);
    }
}
