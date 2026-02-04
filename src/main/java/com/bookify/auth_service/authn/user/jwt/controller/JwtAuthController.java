package com.bookify.auth_service.authn.user.jwt.controller;
import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.user.jwt.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.jwt.dto.LoginRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RefreshTokenRequest;
import com.bookify.auth_service.authn.user.jwt.dto.RegisterRequest;
import com.bookify.auth_service.authn.user.jwt.service.UserService;
import jakarta.servlet.http.Cookie;
import jakarta.validation.Valid;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpServletRequest;

import java.time.Duration;
import java.util.Arrays;
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

    @GetMapping("/me")
    public ResponseEntity<UserDto> me(@AuthenticationPrincipal CustomUserDetails user) {
        return ResponseEntity.ok(UserDto.from(user));

    }

    // ===== Register =====
    @PostMapping("/register")
    public ResponseEntity<?> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseEntity.ok(userService.registerUser(request));

    }

    // ===== Login =====
    @PostMapping("/login")
    public ResponseEntity<Void> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletResponse response
    ) {
        JwtAuthResponse authResponse = userService.loginUser(request);

        // Access token cookie
        ResponseCookie accessCookie = ResponseCookie.from(
                        "accessToken", authResponse.getAccessToken())
                .httpOnly(true)
                .secure(false) // true in prod
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .build();

        // Refresh token cookie
        ResponseCookie refreshCookie = ResponseCookie.from(
                        "refreshToken", authResponse.getRefreshToken())
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth/jwt/refresh")
                .maxAge(Duration.ofDays(7))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());

        // No tokens in body anymore
        return ResponseEntity.ok().build();
    }



    // ===== Logout =====
    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        // 1️⃣ Extract refresh token from cookie
        String refreshToken = null;
        if (request.getCookies() != null) {
            refreshToken = Arrays.stream(request.getCookies())
                    .filter(c -> "refreshToken".equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        // 2️⃣ Logout logic (DB / blacklist)
        if (refreshToken != null) {
            userService.logoutUser(refreshToken);
        }

        // 3️⃣ Clear access token cookie
        ResponseCookie clearAccess = ResponseCookie.from("accessToken", "")
                .httpOnly(true)
                .secure(false) // true in prod
                .sameSite("Lax")
                .path("/")
                .maxAge(0)
                .build();

        // 4️⃣ Clear refresh token cookie
        ResponseCookie clearRefresh = ResponseCookie.from("refreshToken", "")
                .httpOnly(true)
                .secure(false)
                .sameSite("Lax")
                .path("/api/auth/jwt/refresh")
                .maxAge(0)
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, clearAccess.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, clearRefresh.toString());

        return ResponseEntity.ok(
                Map.of("message", "Logged out successfully")
        );
    }


    // ===== Refresh =====
    @PostMapping("/refresh")
    public ResponseEntity<Void> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response
    ) {
        // 1️⃣ Extract refresh token from cookie
        String refreshToken = Arrays.stream(request.getCookies())
                .filter(c -> "refreshToken".equals(c.getName()))
                .findFirst()
                .orElseThrow(() -> new RuntimeException("Refresh token missing"))
                .getValue();

        RefreshTokenRequest refreshTokenRequest = new RefreshTokenRequest();
        refreshTokenRequest.setRefreshToken(refreshToken);


        // 2️⃣ Refresh tokens using existing service logic
        JwtAuthResponse authResponse =
                userService.refreshToken(refreshTokenRequest);

        // 3️⃣ Update access token cookie
        ResponseCookie accessCookie = ResponseCookie.from(
                        "accessToken", authResponse.getAccessToken())
                .httpOnly(true)
                .secure(false) // true in prod
                .sameSite("Lax")
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessCookie.toString());

        // 4️⃣ OPTIONAL: rotate refresh token
        if (authResponse.getRefreshToken() != null) {
            ResponseCookie refreshCookie = ResponseCookie.from(
                            "refreshToken", authResponse.getRefreshToken())
                    .httpOnly(true)
                    .secure(false)
                    .sameSite("Lax")
                    .path("/api/auth/jwt/refresh")
                    .maxAge(Duration.ofDays(7))
                    .build();

            response.addHeader(HttpHeaders.SET_COOKIE, refreshCookie.toString());
        }

        // 5️⃣ No tokens in response body
        return ResponseEntity.ok().build();
    }


}

