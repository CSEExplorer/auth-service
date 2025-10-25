package com.bookify.auth_service.authn.user.oauth.external.service;


import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.repository.BasicUserRepository;
import com.bookify.auth_service.authn.user.jwt.service.JwtService;
import lombok.Getter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import org.springframework.http.*;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Service
public class GoogleOAuthService {

    private final String TOKEN_URI = "https://oauth2.googleapis.com/token";
    private final String USER_INFO_URI = "https://www.googleapis.com/oauth2/v2/userinfo";

    @Value("${oauth2.client.google.client-id}")
    private String clientId;

    @Value("${oauth2.client.google.client-secret}")
    private String clientSecret;

    @Value("${oauth2.client.google.redirect-uri}")
    private String redirectUri;

    private final BasicUserRepository userRepository;
    private final JwtService jwtService;

    @Getter
    private String userEmail; // store email temporarily for SecurityContext

    public GoogleOAuthService(BasicUserRepository userRepository, JwtService jwtService) {
        this.userRepository = userRepository;
        this.jwtService = jwtService;
    }

    public String processOAuthCode(String code) {
        // 1️⃣ Exchange code for Google access token (simplified)
        String accessToken = exchangeCodeForToken(code);
        System.out.println("access token"+accessToken);
        // 2️⃣ Get user info from Google
        GoogleUserInfo googleUser = fetchGoogleUserInfo(accessToken);

        // 3️⃣ Load or create user in your DB
        User user = userRepository.findByEmail(googleUser.email())
                .orElseGet(() -> userRepository.save(
                        User.builder()
                                .username(googleUser.name())
                                .email(googleUser.email())
                                .passwordHash("")
                                .isActive(true)
                                .build()
                ));

        this.userEmail = user.getEmail();
        System.out.println("Email"+userEmail);
        CustomUserDetails userDetails = new CustomUserDetails(user);

//        List<String> scopes = List.of("read", "write");
//        List<String> roles = List.of("ROLE_USER");

        // 4️⃣ Generate JWT for your app
        return jwtService.generateAccessToken(userDetails,null,null,null);
    }

    private String exchangeCodeForToken(String code) {

        RestTemplate restTemplate = new RestTemplate();

        // Prepare request body
        Map<String, String> body = new HashMap<>();
        body.put("code", code);
        body.put("client_id", clientId);
        body.put("client_secret", clientSecret);
        body.put("redirect_uri", redirectUri);
        body.put("grant_type", "authorization_code");

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        // Convert body map to URL-encoded string
        StringBuilder requestBody = new StringBuilder();
        body.forEach((key, value) -> requestBody.append(key).append("=").append(value).append("&"));
        requestBody.deleteCharAt(requestBody.length() - 1); // remove last &

        HttpEntity<String> request = new HttpEntity<>(requestBody.toString(), headers);

        ResponseEntity<Map> response = restTemplate.postForEntity(TOKEN_URI, request, Map.class);

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            return (String) response.getBody().get("access_token");
        }

        throw new RuntimeException("Failed to exchange code for access token");
    }


    private GoogleUserInfo fetchGoogleUserInfo(String accessToken) {



        RestTemplate restTemplate = new RestTemplate();

        // Set Authorization header
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);
        HttpEntity<String> entity = new HttpEntity<>(headers);

        // Make GET request to fetch user info
        ResponseEntity<Map> response = restTemplate.exchange(
                USER_INFO_URI,
                HttpMethod.GET,
                entity,
                Map.class
        );

        if (response.getStatusCode() == HttpStatus.OK && response.getBody() != null) {
            Map<String, Object> userInfoMap = response.getBody();
            String name = (String) userInfoMap.get("name");
            String email = (String) userInfoMap.get("email");
            return new GoogleUserInfo(name, email);
        }

        throw new RuntimeException("Failed to fetch user info from Google");
    }


    public record GoogleUserInfo(String name, String email) {}
}

