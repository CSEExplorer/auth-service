package com.bookify.auth_service.authn.exception.jwt;

public class UserNotFoundException extends RuntimeException {
    public UserNotFoundException(String message) { super(message); }
}