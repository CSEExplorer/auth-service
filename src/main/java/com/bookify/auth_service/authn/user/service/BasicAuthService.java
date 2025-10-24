package com.bookify.auth_service.authn.user.service;

import com.bookify.auth_service.authn.exception.basic.CustomAuthException;
import com.bookify.auth_service.authn.user.dto.BasicAuthResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.bookify.auth_service.authn.user.dto.LoginRequest;
import com.bookify.auth_service.authn.user.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.entity.User;
import com.bookify.auth_service.authn.user.repository.BasicUserRepository;
import com.bookify.auth_service.authn.utility.PasswordEncoderUtil;

import java.util.UUID;

@Service
@RequiredArgsConstructor
public class BasicAuthService {

    private final BasicUserRepository basicUserRepository;
    private final AuthenticationManager authenticationManager;
    

    // ---------------- REGISTER USER ----------------
    public String register(RegisterRequest request) {
        if (basicUserRepository.existsByUsername(request.getUsername())) {
            throw new RuntimeException("Username already exists");
        }

        if (basicUserRepository.existsByEmail(request.getEmail())) {
            throw new RuntimeException("Email already exists");
        }

        
		String hashedPassword = PasswordEncoderUtil.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(hashedPassword)
                .isActive(true)
                .build();

        basicUserRepository.save(user);
        return "User registered successfully!";
    }

    // ---------------- AUTHENTICATE USER ----------------
    public  BasicAuthResponse   authenticate(LoginRequest request) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsernameOrEmail(),
                            request.getPassword()
                    )
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
            Authentication auth = SecurityContextHolder.getContext().getAuthentication();
            System.out.println("Principal: " + auth.getPrincipal());
            System.out.println("Authorities: " + auth.getAuthorities());
            System.out.println("Credentials: " + auth.getCredentials());
            System.out.println("Details: " + auth.getDetails());
            System.out.println("Authenticated: " + auth.isAuthenticated());
            // Generate a mock token (replace later with JWT)
            String token = UUID.randomUUID().toString();

            return new BasicAuthResponse(token, "Authentication successful", request.getUsernameOrEmail());

        } catch (BadCredentialsException ex) {
            throw new CustomAuthException("Invalid username/email or password");
        }
    }
}
