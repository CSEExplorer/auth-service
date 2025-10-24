package com.bookify.auth_service.authn.exception.jwt;

public class UsernameAlreadyExistsException extends RuntimeException {
    public UsernameAlreadyExistsException(String message) { super(message); }
}
