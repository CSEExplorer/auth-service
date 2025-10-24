package com.bookify.auth_service.authn.security;



import com.bookify.auth_service.authn.exception.jwt.JwtTokenExpiredException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenRevokedException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenInvalidException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;

import java.io.IOException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.ServletException;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request,
                         HttpServletResponse response,
                         AuthenticationException authException) throws IOException, ServletException {

        response.setContentType("application/json");
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);

        Map<String, Object> body = new HashMap<>();
        body.put("timestamp", Instant.now().toString());
        body.put("status", HttpServletResponse.SC_UNAUTHORIZED);

        // Traverse cause to find the actual custom exception
        Throwable cause = authException;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }

        if (cause instanceof JwtTokenExpiredException) {
            body.put("error", "TokenExpired");
            body.put("message", cause.getMessage());
        } else if (cause instanceof JwtTokenRevokedException) {
            body.put("error", "TokenRevoked");
            body.put("message", cause.getMessage());
        } else if (cause instanceof JwtTokenInvalidException) {
            body.put("error", "TokenInvalid");
            body.put("message", cause.getMessage());
        } else if (cause instanceof io.jsonwebtoken.security.SignatureException) {
            body.put("error", "SignatureMismatch");
            body.put("message", "JWT signature does not match. Token may be invalid or server restarted with a new key pair.");
        } else {
            body.put("error", "Unauthorized");
            body.put("message", authException.getMessage());
        }

        response.getWriter().write(objectMapper.writeValueAsString(body));
    }
}
