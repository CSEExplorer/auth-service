package com.bookify.auth_service.authn.user.jwt.service;

import com.bookify.auth_service.authn.exception.basic.CustomAuthException;
import com.bookify.auth_service.authn.user.jwt.dto.BasicAuthResponse;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;

import com.bookify.auth_service.authn.user.jwt.dto.LoginRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.repository.BasicUserRepository;
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

    @Transactional
    public void resetPassword(UUID userId, String newPassword) {
        System.out.println("Hey i have got the request to change password and I am changing it ");
        User user = basicUserRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String encoded = PasswordEncoderUtil.encode(newPassword);
        user.setPasswordHash(encoded);
        basicUserRepository.save(user);
    }


    public UUID findUserIdByEmail(String email) {
        return basicUserRepository.findByEmail(email)
                .map(User::getId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }


}
