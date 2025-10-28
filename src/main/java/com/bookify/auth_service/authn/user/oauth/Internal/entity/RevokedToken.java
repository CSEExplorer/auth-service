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
@Table(name = "revoked_tokens")
public class RevokedToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    @Column(name = "token_id")
    private UUID tokenId;

    @Column(name = "client_id")
    private String clientId;

    @Column(name = "principal_name")
    private String principalName;

    @CreationTimestamp
    @Column(name = "revoked_at", updatable = false)
    private Instant revokedAt;

    @Column(name = "reason")
    private String reason;
}

