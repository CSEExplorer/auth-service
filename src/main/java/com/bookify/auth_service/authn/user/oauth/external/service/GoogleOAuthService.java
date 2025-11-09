package com.bookify.auth_service.authn.user.oauth.external.service;

import com.auth0.jwt.JWT;

import com.auth0.jwt.interfaces.DecodedJWT;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class GoogleOAuthService {

    private static final String TOKEN_URI = "https://oauth2.googleapis.com/token";
    private static final String USER_INFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo";

    @Value("${oauth2.client.google.client-id}")
    private String clientId;

    @Value("${oauth2.client.google.client-secret}")
    private String clientSecret;

    @Value("${oauth2.client.google.redirect-uri}")
    private String redirectUri;

    private final RestTemplate restTemplate = new RestTemplate();

    /**
     * Exchanges the authorization code for Google tokens.
     */
    public Map<String, String> exchangeCodeForToken(String code) {
        Map<String, String> body = Map.of(
                "code", code,
                "client_id", clientId,
                "client_secret", clientSecret,
                "redirect_uri", redirectUri,
                "grant_type", "authorization_code"
        );

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        String formBody = body.entrySet().stream()
                .map(entry -> entry.getKey() + "=" + entry.getValue())
                .reduce((a, b) -> a + "&" + b)
                .orElse("");

        ResponseEntity<Map> response = restTemplate.postForEntity(
                TOKEN_URI,
                new HttpEntity<>(formBody, headers),
                Map.class
        );

        if (response.getStatusCode() != HttpStatus.OK || response.getBody() == null)
            throw new RuntimeException("Failed to exchange code for token");

        Map<String, String> tokens = new HashMap<>();
        tokens.put("access_token", (String) response.getBody().get("access_token"));
        tokens.put("id_token", (String) response.getBody().get("id_token"));
        return tokens;
    }

    /**
     * Extract user info (name/email) from Google’s ID token.
     */
    public GoogleUserInfo decodeIdToken(String idToken) {
        DecodedJWT jwt = JWT.decode(idToken);
        return new GoogleUserInfo(
                jwt.getClaim("name").asString(),
                jwt.getClaim("email").asString()
        );
    }

    public record GoogleUserInfo(String name, String email) {}
}
