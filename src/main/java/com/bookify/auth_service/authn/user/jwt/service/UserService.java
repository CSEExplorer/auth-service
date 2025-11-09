package com.bookify.auth_service.authn.user.jwt.service;

import com.bookify.auth_service.authn.exception.jwt.EmailAlreadyExistsException;
import com.bookify.auth_service.authn.exception.jwt.InvalidCredentialsException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenInvalidException;
import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.security.CustomUserDetailsService;
import com.bookify.auth_service.authn.user.jwt.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.jwt.dto.LoginRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RefreshTokenRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.jwt.entity.Role;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.event.EmailEvent;
import com.bookify.auth_service.authn.user.jwt.repository.RefreshTokenRepository;
import com.bookify.auth_service.authn.user.jwt.repository.UserRepository;
import com.bookify.auth_service.authn.user.jwt.service.producer.EmailEventProducer;
import com.bookify.auth_service.authn.utility.PasswordEncoderUtil;
import com.bookify.auth_service.authn.utility.UsernameGenerator;
import jakarta.transaction.Transactional;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Service
public class UserService {

    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final TokenBlacklistService tokenBlacklistService;
    private final RefreshTokenRepository refreshTokenRepository;
    private Authentication authentication;
    private final EmailEventProducer emailEventProducer;

  UserService(AuthenticationManager authenticationManager, JwtService jwtService, CustomUserDetailsService userDetailsService, UserRepository userRepository, PasswordEncoder passwordEncoder, TokenBlacklistService tokenBlacklistService, RefreshTokenRepository refreshTokenRepository, EmailEventProducer emailEventProducer){
      this.authenticationManager = authenticationManager;
      this.jwtService = jwtService;

      this.userRepository = userRepository;
      this.passwordEncoder = passwordEncoder;
      this.tokenBlacklistService = tokenBlacklistService;
      this.refreshTokenRepository = refreshTokenRepository;
      this.emailEventProducer = emailEventProducer;
  }

    @Transactional
    public void resetPassword(UUID userId, String newPassword) {
        System.out.println("Hey i have got the request to change password and I am changing it ");
        User user = userRepository.findById(userId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));

        String encoded = PasswordEncoderUtil.encode(newPassword);
        user.setPasswordHash(encoded);
        userRepository.save(user);
    }

    public UUID findUserIdByEmail(String email) {
        return userRepository.findByEmail(email)
                .map(User::getId)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
    }

    public JwtAuthResponse loginUser(LoginRequest request) {
        try {
            String identifier = request.getUsernameOrEmail();

            // 1️⃣ Determine whether input is email or username
            boolean isEmail = identifier.contains("@");

            // 2️⃣ Find user by email or username
            Optional<User> optionalUser = isEmail
                    ? userRepository.findByEmail(identifier)
                    : userRepository.findByUsername(identifier);

            // 3️⃣ Authenticate using the actual username (email or username)
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            identifier, // can be email or username
                            request.getPassword()
                    )
            );

            CustomUserDetails customUserDetails = (CustomUserDetails) authentication.getPrincipal();

            User user = optionalUser.orElseThrow(() -> new InvalidCredentialsException("User not found"));

            // 3️⃣ Prepare roles/scopes
            List<String> scopes = List.of("read", "write");
            List<String> roles = user.getRole() != null
                    ? List.of(user.getRole().name())
                    : List.of();

            String email = user.getEmail();

            // 4️⃣ Generate tokens
            String accessToken = jwtService.generateAccessToken(customUserDetails, scopes, roles, null, email);
            String refreshToken = jwtService.generateRefreshToken(user);

            // 5️⃣ Publish login event (for audit / notification)
            EmailEvent event = EmailEvent.builder()
                    .eventType("USER_LOGIN")
                    .userId(user.getId().toString())
                    .channel("EMAIL")
                    .recipient(user.getEmail())
                    .data(Map.of(
                            "userName", user.getUsername(),
                            "loginTime", user.getCreatedAt(),
                            "ipAddress", "",  // Optional, can be fetched from request
                            "location", ""
                    ))
                    .build();

            emailEventProducer.publishEmailEvent(event);

            // 6️⃣ Return tokens
            return new JwtAuthResponse(accessToken, refreshToken);

        } catch (BadCredentialsException e) {
            throw new InvalidCredentialsException("Invalid email or password");
        }
    }


    public Map<String, Object> registerUser(RegisterRequest request) {

        // 1️⃣ Email check
        if (userRepository.existsByEmail(request.getEmail())) {
            throw new EmailAlreadyExistsException("Email already exists");
        }

        // 2️⃣ Hash password
        String hashedPassword = passwordEncoder.encode(request.getPassword());

        // 3️⃣ Determine role
        Role role = Optional.ofNullable(request.getRole())
                .map(Role::valueOf)
                .orElse(Role.USER);

        // 4️⃣ Generate unique username from email
        String username = generateUniqueUsername(request.getEmail());

        // 5️⃣ Create new user
        User user = User.builder()
                .username(username)
                .email(request.getEmail())
                .passwordHash(hashedPassword)
                .role(role)
                .isActive(true)
                .build();

        // 6️⃣ Save user
        userRepository.save(user);

        // 7️⃣ Send registration event (e.g., for email confirmation)
        EmailEvent event = EmailEvent.builder()
                .eventType("USER_REGISTERED")
                .userId(user.getId().toString())
                .channel("EMAIL")
                .recipient(user.getEmail())
                .data(Map.of(
                        "userName", user.getUsername()
                ))
                .build();

        emailEventProducer.publishEmailEvent(event);

        // 8️⃣ Return response
        return Map.of(
                "message", "User registered successfully",
                "userId", user.getId(),
                "username", user.getUsername(),
                "email",user.getEmail()
        );
    }

    public void logoutUser(String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            throw new JwtTokenInvalidException("Please send a valid Bearer token");
        }

        String token = authHeader.substring(7);
        System.out.println(token);
        // Extract username and jti
        String username = jwtService.extractUsername(token);
        String jti = jwtService.extractJti(token);

        // Find user
        User user = userRepository.findByUsernameOrEmail(username)
                .orElseThrow(() -> new JwtTokenInvalidException("User not found"));

        // Calculate remaining TTL and blacklist token
        Duration ttl = Duration.between(
                java.time.Instant.now(),
                jwtService.extractExpiration(token).toInstant()
        );
        tokenBlacklistService.blacklistToken(jti, ttl);

        // Revoke refresh tokens
        jwtService.revokeAllRefreshTokens(user);

        // Optionally emit a logout event
//        EmailEvent event = EmailEvent.builder()
//                .eventType("USER_LOGOUT")
//                .userId(user.getId().toString())
//                .channel("EMAIL")
//                .recipient(user.getEmail())
//                .data(Map.of(
//                        "userName", user.getUsername(),
//                        "logoutTime", java.time.Instant.now().toString()
//                ))
//                .build();
//
//        emailEventProducer.publishEmailEvent(event);

    }


    public JwtAuthResponse refreshToken(RefreshTokenRequest request) {
        String oldRefreshToken = request.getRefreshToken();

        // 1️⃣ Rotate token and detect reuse
        String newRefreshToken = jwtService.rotateRefreshToken(oldRefreshToken);

        // 2️⃣ Find user from rotated token
        User user = refreshTokenRepository.findAll().stream()
                .filter(t -> passwordEncoder.matches(newRefreshToken, t.getTokenHash()))
                .findFirst()
                .orElseThrow(() -> new JwtTokenInvalidException("User not found for refresh token"))
                .getUser();

        CustomUserDetails customUserDetails = new CustomUserDetails(user);

// 4️⃣ Generate new access token
        List<String> scopes = List.of("read", "write");
        List<String> roles = user.getRole() != null
                ? List.of(user.getRole().name())
                : List.of();

        String email = user.getEmail();
        String newAccessToken = jwtService.generateAccessToken(customUserDetails, scopes, roles, null, email);

//        // 5️⃣ Optionally emit event
//        EmailEvent event = EmailEvent.builder()
//                .eventType("USER_REFRESHED_TOKEN")
//                .userId(user.getId().toString())
//                .channel("EMAIL")
//                .recipient(user.getEmail())
//                .data(Map.of(
//                        "userName", user.getUsername(),
//                        "time", java.time.Instant.now().toString()
//                ))
//                .build();
//
//        emailEventProducer.publishEmailEvent(event);

        // 6️⃣ Return response
        return new JwtAuthResponse(newAccessToken, newRefreshToken);
    }
    private String generateUniqueUsername(String email) {
        String base = UsernameGenerator.generateBaseFromEmail(email);
        String username = base;
        int attempt = 1;

        while (userRepository.existsByUsername(username)) {
            username = base + attempt;
            attempt++;

            if (attempt > 5) {
                username = base + "_" + UsernameGenerator.randomDigits(4);
                break;
            }
        }

        return username;
    }

}
