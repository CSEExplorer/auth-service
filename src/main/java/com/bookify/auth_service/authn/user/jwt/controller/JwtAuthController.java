package com.bookify.auth_service.authn.user.jwt.controller;
import com.bookify.auth_service.authn.user.jwt.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.jwt.dto.LoginRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RefreshTokenRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.jwt.service.UserService;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import com.bookify.auth_service.authn.user.jwt.dto.*;
import org.springframework.web.bind.annotation.*;


@RestController
@RequestMapping("/api/auth/jwt")
public class JwtAuthController {

    private final UserService userService;

    public JwtAuthController(UserService userService) {
        this.userService = userService;
    }

    // ===== Register =====
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(userService.registerUser(request));

    }

    // ===== Login =====
    @PostMapping("/login")
    public ResponseEntity<JwtAuthResponse> login(@Valid @RequestBody LoginRequest request) {
        return ResponseEntity.ok(userService.loginUser(request));
    }


    // ===== Logout =====
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        userService.logoutUser(authHeader);
        return ResponseEntity.ok(
                Map.of("message", "Logged out successfully, access token blacklisted and refresh tokens revoked")
        );
    }

    // ===== Refresh =====
    @PostMapping("/refresh")
    public ResponseEntity<JwtAuthResponse> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseEntity.ok(userService.refreshToken(request));
    }

}

