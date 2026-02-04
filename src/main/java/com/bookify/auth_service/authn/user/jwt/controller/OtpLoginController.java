package com.bookify.auth_service.authn.user.jwt.controller;

import com.bookify.auth_service.authn.user.jwt.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.jwt.dto.OtpRequest;
import com.bookify.auth_service.authn.user.jwt.dto.OtpVerifyRequest;
import com.bookify.auth_service.authn.user.jwt.service.OtpAuthService;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Duration;

@RestController
@RequestMapping("/auth/otp")
@RequiredArgsConstructor
public class OtpLoginController {

    private final OtpAuthService otpAuthService;

    @PostMapping("/login")
    public ResponseEntity<Void> loginWithOtp(
            @Valid @RequestBody OtpVerifyRequest request,
            HttpServletResponse response
    ) {
        JwtAuthResponse authResponse =
                otpAuthService.verifyOtp(request);

        // 🍪 Access Token Cookie (short-lived)
        ResponseCookie accessTokenCookie = ResponseCookie.from(
                        "accessToken", authResponse.getAccessToken()
                )
                .httpOnly(true)
                .secure(true)
                .path("/")
                .maxAge(Duration.ofMinutes(15))
                .sameSite("Strict")
                .build();

        // 🍪 Refresh Token Cookie (long-lived)
        ResponseCookie refreshTokenCookie = ResponseCookie.from(
                        "refreshToken", authResponse.getRefreshToken()
                )
                .httpOnly(true)
                .secure(true)
                .path("/auth/refresh")
                .maxAge(Duration.ofDays(7))
                .sameSite("Strict")
                .build();

        response.addHeader(HttpHeaders.SET_COOKIE, accessTokenCookie.toString());
        response.addHeader(HttpHeaders.SET_COOKIE, refreshTokenCookie.toString());

        return ResponseEntity.ok().build();
    }

    @PostMapping("/request")
    public ResponseEntity<Void> requestOtp(
            @Valid @RequestBody OtpRequest request
    ) {
        otpAuthService.sendOtp(request.getEmail());
        return ResponseEntity.ok().build();
    }

}

