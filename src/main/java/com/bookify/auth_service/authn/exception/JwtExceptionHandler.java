package com.bookify.auth_service.authn.exception;



import com.bookify.auth_service.authn.exception.jwt.*;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@RestControllerAdvice
public class JwtExceptionHandler {

    @ExceptionHandler(EmailAlreadyExistsException.class)
    public ResponseEntity<String> handleEmailExists(EmailAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    @ExceptionHandler(UsernameAlreadyExistsException.class)
    public ResponseEntity<String> handleUsernameExists(UsernameAlreadyExistsException ex) {
        return ResponseEntity.status(HttpStatus.CONFLICT).body(ex.getMessage());
    }

    @ExceptionHandler(InvalidCredentialsException.class)
    public ResponseEntity<String> handleInvalidCredentials(InvalidCredentialsException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }

    @ExceptionHandler(UserNotFoundException.class)
    public ResponseEntity<String> handleUserNotFound(UserNotFoundException ex) {
        return ResponseEntity.status(HttpStatus.NOT_FOUND).body(ex.getMessage());
    }

    @ExceptionHandler(JwtTokenInvalidException.class)
    public ResponseEntity<String> handleJwtInvalid(JwtTokenInvalidException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(ex.getMessage());
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<String> handleOtherExceptions(Exception ex) {
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(ex.getMessage());
    }

    // ===== 4. JWT expired =====
    @ExceptionHandler(io.jsonwebtoken.ExpiredJwtException.class)
    public ResponseEntity<String> handleExpiredJwt(io.jsonwebtoken.ExpiredJwtException ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                .body("Token expired, please refresh");
    }
    @ExceptionHandler({
            io.jsonwebtoken.MalformedJwtException.class,
            IllegalArgumentException.class
    })
    public ResponseEntity<String> handleInvalidJwt(Exception ex) {
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid JWT token");
    }

    @ExceptionHandler(JwtTokenExpiredException.class)
    public ResponseEntity<Map<String, Object>> handleExpiredToken(JwtTokenExpiredException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", "Access token expired");
        body.put("details", "Please refresh your token or login again.");
        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }

    @ExceptionHandler(JwtTokenRevokedException.class)
    public ResponseEntity<Map<String, Object>> handleRevokedToken(JwtTokenRevokedException ex) {
        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", HttpStatus.UNAUTHORIZED.value());
        body.put("error", "Unauthorized");
        body.put("message", ex.getMessage());
        body.put("details", "Your access token has been revoked. Please login again.");

        return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(body);
    }



}

