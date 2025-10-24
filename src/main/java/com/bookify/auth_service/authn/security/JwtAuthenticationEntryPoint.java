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
import java.time.Instant;

@Component
public class JwtAuthenticationEntryPoint implements AuthenticationEntryPoint {

    @Override
    public void commence(
            HttpServletRequest request,
            HttpServletResponse response,
            AuthenticationException authException
    ) throws IOException {

        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");

        int status = HttpServletResponse.SC_UNAUTHORIZED; // 401
        String message = "Unauthorized";

        // Customize message based on the exception
        Throwable cause = authException.getCause();
        if (cause instanceof JwtTokenExpiredException) {
            message = cause.getMessage(); // "Token has expired"
        } else if (cause instanceof JwtTokenRevokedException) {
            message = cause.getMessage(); // "Token has been revoked"
        } else if (cause instanceof JwtTokenInvalidException) {
            message = cause.getMessage(); // "Invalid token"
        } else {
            message = authException.getMessage();
        }

        String json = String.format(
                "{\"timestamp\":\"%s\",\"status\":%d,\"error\":\"Unauthorized\",\"message\":\"%s\",\"path\":\"%s\"}",
                Instant.now().toString(),
                status,
                message,
                request.getRequestURI()
        );

        response.setStatus(status);
        response.getWriter().write(json);
    }
}

