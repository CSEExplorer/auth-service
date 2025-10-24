package com.bookify.auth_service.authn.exception.redis;

import org.springframework.data.redis.RedisConnectionFailureException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;

@ControllerAdvice
public class RedisExceptionHandler {

    @ExceptionHandler(RedisConnectionFailureException.class)
    public ResponseEntity<String> handleRedisDown(RedisConnectionFailureException ex) {
        return ResponseEntity.status(HttpStatus.SERVICE_UNAVAILABLE)
                .body("Token revocation service unavailable, please try again later");
    }
}
