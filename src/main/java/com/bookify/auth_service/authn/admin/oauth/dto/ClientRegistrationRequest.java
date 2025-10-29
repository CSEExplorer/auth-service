package com.bookify.auth_service.authn.admin.oauth.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;
import java.util.Set;

/**
 * DTO for Admin API client registration.
 * Represents a new OAuth2 client registration request.
 */
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ClientRegistrationRequest {

    /**
     * The unique client identifier for the OAuth2 client.
     */
    private String clientId;

    /**
     * The client secret (hashed or plain depending on setup).
     */
    private String clientSecret;

    /**
     * Allowed redirect URIs for authorization code or implicit flows.
     */
    private Set<String> redirectUris;

    /**
     * Scopes allowed for this client (e.g., openid, profile, email).
     */
    private Set<String> scopes;

    /**
     * Supported OAuth2 grant types (e.g., authorization_code, client_credentials, refresh_token).
     */
    private Set<String> grantTypes;

    /**
     * Client authentication method (e.g., client_secret_basic, client_secret_post, none).
     */
    private String clientAuthMethod;

    /**
     * Human-readable client name for admin UI.
     */
    private String clientName;

    private TokenSettingsDTO  tokenSettings;
}
