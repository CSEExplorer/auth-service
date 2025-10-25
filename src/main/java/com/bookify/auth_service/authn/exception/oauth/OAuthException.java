package com.bookify.auth_service.authn.exception.oauth;


public class OAuthException extends RuntimeException {
    private final int status;

    public OAuthException(String message, int status) {
        super(message);
        this.status = status;
    }

    public int getStatus() {
        return status;
    }
}
