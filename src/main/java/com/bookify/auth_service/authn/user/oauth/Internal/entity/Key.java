package com.bookify.auth_service.authn.user.oauth.Internal.entity;


import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(name = "keys")
public class Key {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    @Column(name = "kid", nullable = false, unique = true)
    private String kid;

    @Column(name = "algorithm", nullable = false)
    private String algorithm; // e.g., RS256, ES256

    @Lob
    @Column(name = "public_key_pem", columnDefinition = "TEXT", nullable = false)
    private String publicKeyPem;

    @Lob
    @Column(name = "private_key_encrypted", columnDefinition = "TEXT")
    private String privateKeyEncrypted; // Optional: encrypted or null if external KMS used

    @Column(name = "use", nullable = false)
    private String use; // sig or enc

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @Column(name = "active", nullable = false)
    private boolean active = true;
}

