package com.bookify.auth_service.authn.user.oauth.Internal.entity;


import jakarta.persistence.*;
import lombok.*;
import java.time.Instant;

@Entity
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Table(name = "jwks")
public class JwkEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false, unique = true)
    private String keyId;

    @Lob
    @Column(nullable = false)
    private String publicKeyJson;  // JWK public key (for JWKS endpoint)

    @Lob
    @Column(nullable = false)
    private String privateKeyJson; // Private JWK

    @Column(nullable = false)
    private boolean active;  // Only one key active for signing

    @Column(nullable = false)
    private Instant createdAt;
}

