package com.bookify.auth_service.authn.exception.jwt;

public class JwtTokenInvalidException extends RuntimeException {
    public JwtTokenInvalidException(String message) { super(message); }
}