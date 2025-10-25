package com.bookify.auth_service.authn.user.oauth.external.service;


import com.auth0.jwt.interfaces.Claim;
import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.repository.BasicUserRepository;
import com.bookify.auth_service.authn.user.jwt.service.JwtService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.auth0.jwt.JWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;
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
import java.util.Optional;

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
        Map<String, String> googleTokens = exchangeCodeForToken(code);
        String idToken = googleTokens.get("id_token");
        String accessToken = googleTokens.get("access_token");

        // 2️⃣ Get user info from Google
        GoogleUserInfo googleUser = decodeIdToken(idToken);
//         3️⃣ Load or create user in your DB
        Optional<User> existingUserOpt = userRepository.findByEmail(googleUser.email());

        User user;
        if (existingUserOpt.isPresent()) {
            // Duplicate user found
            user = existingUserOpt.get();
            // You can handle duplicate logic here, e.g., return a message or update refresh token
            System.out.println("User already exists: " + user.getEmail());
        } else {
            // New user → save to DB
            user = userRepository.save(
                    User.builder()
                            .username(googleUser.name())
                            .email(googleUser.email())
                            .passwordHash("") // empty for OAuth user
                            .isActive(true)
                            .build()
            );
            System.out.println("New user created: " + user.getEmail());
        }



        this.userEmail = user.getEmail();
        System.out.println("Email"+userEmail);
        CustomUserDetails userDetails = new CustomUserDetails(user);

//        List<String> scopes = List.of("read", "write");
//        List<String> roles = List.of("ROLE_USER");

        // 4️⃣ Generate JWT for your app
        // this method saves refresh token as well as stores it also

         String jwtRefreshToken = jwtService.generateRefreshToken(user);
         System.out.println("Save the refresh token because it will be hashed");
         System.out.println(jwtRefreshToken);
        return jwtService.generateAccessToken(userDetails,null,null,null);
    }

    private Map<String, String> exchangeCodeForToken(String code) {

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
            try {
                ObjectMapper mapper = new ObjectMapper();
                mapper.enable(SerializationFeature.INDENT_OUTPUT); // pretty-print
                String json = mapper.writeValueAsString(response.getBody());
                System.out.println("Full JSON response from Google:");
                System.out.println(json);
            } catch (JsonProcessingException e) {
                System.err.println("Error converting Google response to JSON:");
                e.printStackTrace();
            }
            Map<String, String> tokens = new HashMap<>();
            tokens.put("access_token", (String) response.getBody().get("access_token"));
            tokens.put("id_token", (String) response.getBody().get("id_token"));

            return tokens;
        }

        throw new RuntimeException("Failed to exchange code for access token");
    }


    private GoogleUserInfo fetchGoogleUserInfo(String accessToken) {

       // This is the method can be used later to fetch other resources form the google

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

    private GoogleUserInfo decodeIdToken(String idToken) {
        DecodedJWT decodedJWT = JWT.decode(idToken);

        Map<String, Claim> claims = decodedJWT.getClaims(); // all claims
        Map<String, Object> result = new HashMap<>();

        for (Map.Entry<String, Claim> entry : claims.entrySet()) {
            String key = entry.getKey();
            Claim claim = entry.getValue();

            // Use as(Object.class) to get the raw value
            Object value;
            if (claim.as(Object.class) != null) {
                value = claim.as(Object.class);
            } else {
                value = claim.toString();
            }

            result.put(key, value);
        }

        String email = decodedJWT.getClaim("email").asString();
        String name = decodedJWT.getClaim("name").asString();
        System.out.println("All Claims from id_token");
        System.out.println(result);
        return new GoogleUserInfo(name, email);
    }


    public record GoogleUserInfo(String name, String email) {}
}

