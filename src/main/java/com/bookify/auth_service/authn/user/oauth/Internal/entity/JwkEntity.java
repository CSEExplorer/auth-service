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


    @Basic(fetch = FetchType.EAGER)
    @Column(name = "public_key_json", nullable = false, columnDefinition = "TEXT")
    private String publicKeyJson;

    @Basic(fetch = FetchType.EAGER)
    @Column(name = "private_key_json", nullable = false, columnDefinition = "TEXT")
    private String privateKeyJson;


    private boolean retired;
    private boolean revoked;

    @Column(nullable = false)
    private boolean active;  // Only one key active for signing

    @Column(nullable = false)
    private Instant createdAt;
}

