package com.bookify.auth_service.authn.user.oauth.external.controller;


import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

@RestController
@RequestMapping("/api/auth/oauth")
public class OAuthController {

    @Value("${oauth2.client.google.client-id}")
    private String clientId;

    @Value("${oauth2.client.google.redirect-uri}")
    private String redirectUri;

    @GetMapping("/login/google")
    public ResponseEntity<Void> redirectToGoogle() {
        String encodedRedirectUri = URLEncoder.encode(redirectUri, StandardCharsets.UTF_8);
        String encodedScope = URLEncoder.encode("profile email", StandardCharsets.UTF_8);
        String authUrl = "https://accounts.google.com/o/oauth2/v2/auth" +
                "?client_id=" + clientId +
                "&redirect_uri=" + encodedRedirectUri +
                "&response_type=code" +
                "&scope=" + encodedScope;

        return ResponseEntity.status(302).location(URI.create(authUrl)).build();
    }
    @GetMapping("/callback/google")
    public ResponseEntity<Void> handleGoogleCallback() {
        // The GoogleOAuthFilter will intercept this request and process JWT
        // Here, you can just return 200 OK or redirect to frontend
        return ResponseEntity.ok().build();
    }
}

