package com.bookify.auth_service.authn.user.controller;




import com.bookify.auth_service.authn.exception.jwt.EmailAlreadyExistsException;
import com.bookify.auth_service.authn.exception.jwt.InvalidCredentialsException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenInvalidException;
import com.bookify.auth_service.authn.exception.jwt.UsernameAlreadyExistsException;
import com.bookify.auth_service.authn.security.CustomUserDetailsService;
import com.bookify.auth_service.authn.user.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.dto.LoginRequest;
import com.bookify.auth_service.authn.user.dto.RefreshTokenRequest;
import com.bookify.auth_service.authn.user.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.entity.User;
import com.bookify.auth_service.authn.user.repository.BasicUserRepository;
import com.bookify.auth_service.authn.user.repository.RefreshTokenRepository;
import com.bookify.auth_service.authn.user.service.JwtService;
import com.bookify.auth_service.authn.user.service.TokenBlacklistService;
import jakarta.validation.Valid;

import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.util.List;

@RestController
@RequestMapping("/api/auth/jwt")
public class JwtAuthController {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final BasicUserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenRepository refreshTokenRepository;

    public JwtAuthController(AuthenticationManager authenticationManager,
                             JwtService jwtService,
                             CustomUserDetailsService userDetailsService,
                             BasicUserRepository userRepository,
                             PasswordEncoder passwordEncoder,
                             TokenBlacklistService tokenBlacklistService,
                             RefreshTokenRepository refreshTokenRepository) {
        this.authenticationManager = authenticationManager;
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.userRepository = userRepository;
        this.passwordEncoder = passwordEncoder;
        this.tokenBlacklistService = tokenBlacklistService;
        this.refreshTokenRepository = refreshTokenRepository;
    }

    // ===== Register =====
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        if (userRepository.existsByUsername(request.getUsername())) {
            throw new UsernameAlreadyExistsException("Username already exists in the database");
        }

        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists");
        }

        String hashedPassword = passwordEncoder.encode(request.getPassword());

        User user = User.builder()
                .username(request.getUsername())
                .email(request.getEmail())
                .passwordHash(hashedPassword) // Assuming User entity has 'password' field
                .isActive(true)
                .build();

        userRepository.save(user);
        return ResponseEntity.ok(user);
    }

    // ===== Login =====
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@Valid @RequestBody LoginRequest request) {
        try {
            // Authenticate credentials
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            request.getUsernameOrEmail(),
                            request.getPassword()
                    )
            );

            // Load user details and entity
            UserDetails userDetails = userDetailsService.loadUserByUsername(request.getUsernameOrEmail());
            User user = userRepository.findByEmail(request.getUsernameOrEmail())
                    .orElseThrow(() -> new RuntimeException("User not found"));
            List<String> scopes = List.of("read", "write"); // Replace with real scopes
//            List<String> roles = user.getRoles() != null
//                    ? user.getRoles().stream().map(r -> r.getName()).toList()
//                    : List.of();
//            String deviceId = request.getDeviceId(); // optional field in LoginRequest

            // Generate tokens
            String accessToken = jwtService.generateAccessToken(userDetails, scopes, null, null);
            String refreshToken = jwtService.generateRefreshToken(user);

            // Return response
            JwtAuthResponse response = new JwtAuthResponse(accessToken, refreshToken);
            return ResponseEntity.ok(response);

        } catch (BadCredentialsException e) {
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }


    // ===== Logout =====
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new JwtTokenInvalidException("Please send a valid Bearer token");
        }

        String token = authHeader.substring(7);

        // 1️⃣ Extract username and jti
        String username = jwtService.extractUsername(token);
        String jti = jwtService.extractJti(token);
        System.out.println("Decoded username from token = " + username);
        // 2️⃣ Find user
        User user = userRepository.findByEmail(username)
                .orElseThrow(() -> new JwtTokenInvalidException("User not found"));

        // 3️⃣ Blacklist the access token until it expires
        Duration ttl = Duration.between(
                java.time.Instant.now(),
                jwtService.extractExpiration(token).toInstant()
        );
        tokenBlacklistService.blacklistToken(jti, ttl);

        // 4️⃣ Revoke all refresh tokens for this user
        jwtService.revokeAllRefreshTokens(user);

        return ResponseEntity.ok("Logged out successfully, access token blacklisted and refresh tokens revoked");
    }



    // ===== Refresh =====
    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        String oldRefreshToken = request.getRefreshToken();

        // Rotate refresh token and handle reuse detection
        String newRefreshToken = jwtService.rotateRefreshToken(oldRefreshToken);

        // Load user from rotated refresh token
        User user = refreshTokenRepository.findAll().stream()
                .filter(t -> passwordEncoder.matches(newRefreshToken, t.getTokenHash()))
                .findFirst()
                .orElseThrow(() -> new JwtTokenInvalidException("User not found for refresh token"))
                .getUser();

        UserDetails userDetails = userDetailsService.loadUserByUsername(user.getEmail());

        // Optional: scopes/roles
        List<String> scopes = List.of("read", "write");
//        List<String> roles = user.getRoles() != null
//                ? user.getRoles().stream().map(r -> r.getName()).toList()
//                : List.of();

        String newAccessToken = jwtService.generateAccessToken(userDetails, scopes, null, null);

        return ResponseEntity.ok(new JwtAuthResponse(newAccessToken, newRefreshToken));
    }


}

