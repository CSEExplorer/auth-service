package com.bookify.auth_service.authn.exception;



public class CustomAuthException extends RuntimeException {
    public CustomAuthException(String message) {
        super(message);
    }
}
