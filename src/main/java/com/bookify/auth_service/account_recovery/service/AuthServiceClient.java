package com.bookify.auth_service.account_recovery.service;


import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestClient;

import java.util.Map;
import java.util.UUID;

@Component
@RequiredArgsConstructor
public class AuthServiceClient {
    @Value("${auth-service.url}")
    private String authServiceUrl;
    private final RestClient restClient;

    // Example: GET /internal/users/lookup?email=user@example.com
    public UUID getUserIdByEmail(String email) {

        Map<?, ?> response = restClient.get()
                .uri(authServiceUrl +"internal/users/lookup?email={email}", email)
                .retrieve()
                .body(Map.class);

        if (response == null || !response.containsKey("userId")) {
            throw new IllegalArgumentException("No user found for given email");
        }
        return UUID.fromString(response.get("userId").toString());
    }
}

