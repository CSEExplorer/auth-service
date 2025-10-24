package com.bookify.auth_service.authn.exception.basic;



public class CustomAuthException extends RuntimeException {
    public CustomAuthException(String message) {
        super(message);
    }
}
