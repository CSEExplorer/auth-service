package com.bookify.auth_service.authn.user.jwt.controller;



import com.bookify.auth_service.authn.user.jwt.dto.BasicAuthResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.bookify.auth_service.authn.user.jwt.dto.LoginRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.jwt.service.BasicAuthService;

@RestController
@RequestMapping("/api/auth/basic")
@RequiredArgsConstructor
public class BasicAuthController {

    private final BasicAuthService basicAuthService;

    // ---------------- REGISTER USER ----------------
    @PostMapping("/register")
    public ResponseEntity<String> registerUser(@Valid @RequestBody RegisterRequest request) {
        String response = basicAuthService.register(request);
        return ResponseEntity.ok(response);
    }

    // ---------------- AUTHENTICATE USER ----------------
    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@Valid @RequestBody LoginRequest request) {

        BasicAuthResponse response = basicAuthService.authenticate(request);
        return ResponseEntity.ok(response);
    }
}
