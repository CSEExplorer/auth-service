package com.bookify.auth_service.authn.exception.auth;


import org.springframework.http.HttpStatus;

public abstract class AuthException extends RuntimeException {

    private final String code;
    private final HttpStatus status;
    private final Object details;

    protected AuthException(String code, String message, HttpStatus status) {
        this(code, message, status, null);
    }

    protected AuthException(
            String code,
            String message,
            HttpStatus status,
            Object details
    ) {
        super(message);
        this.code = code;
        this.status = status;
        this.details = details;
    }

    public String getCode() {
        return code;
    }

    public HttpStatus getStatus() {
        return status;
    }

    public Object getDetails() {
        return details;
    }
}

