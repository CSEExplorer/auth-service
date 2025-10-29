package com.bookify.auth_service.authn.user.oauth.Internal.entity;



import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "oauth2_client")
public class OAuth2Client {

    @Id
    @Column(name = "client_id", nullable = false, unique = true)
    private String clientId;

    @Column(name = "client_secret", nullable = false)
    private String clientSecret;

    @Column(name = "client_name", nullable = false)
    private String clientName;


    @Column(name = "redirect_uris", columnDefinition = "TEXT")
    private String redirectUris;  // JSON or comma-separated URIs


    @Column(name = "grant_types", columnDefinition = "TEXT")
    private String grantTypes;    // JSON or comma-separated grant types


    @Column(name = "scopes", columnDefinition = "TEXT")
    private String scopes;        // JSON or comma-separated scopes

    @Column(name = "client_auth_method", nullable = false)
    private String clientAuthMethod;


    @Column(name = "token_settings", columnDefinition = "TEXT")
    private String tokenSettings; // JSON structure of token settings

    @Column(name = "jwks", columnDefinition = "TEXT")
    private String jwks;          // Optional JWKS for private_key_jwt clients

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "active", nullable = false)
    private boolean active = true;
}
