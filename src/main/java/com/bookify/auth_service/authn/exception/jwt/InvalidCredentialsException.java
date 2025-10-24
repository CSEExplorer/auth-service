package com.bookify.auth_service.authn.exception.jwt;

public class InvalidCredentialsException extends RuntimeException {
    public InvalidCredentialsException(String message) { super(message); }
}