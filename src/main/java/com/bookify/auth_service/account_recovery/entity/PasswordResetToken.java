package com.bookify.auth_service.account_recovery.entity;

import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;

import java.time.Instant;
import java.util.UUID;

@Entity
@Table(name = "password_reset_tokens",
        indexes = {
                @Index(name = "idx_password_reset_token_token", columnList = "token"),
                @Index(name = "idx_password_reset_token_user_id", columnList = "userId")
        })
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class PasswordResetToken {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    /**
     * Reference to the user (from auth-service DB)
     */
    @Column(nullable = false)
    private UUID userId;

    /**
     * The actual reset token (random string or JWT)
     */
    @Column(nullable = false, unique = true, length = 255)
    private String token;

    /**
     * Expiry timestamp (e.g., 15 min from generation)
     */
    @Column(nullable = false)
    private Instant expiresAt;

    /**
     * True if already used
     */
    @Column(nullable = false)
    private boolean used;

    @CreationTimestamp
    @Column(nullable = false, updatable = false)
    private Instant createdAt;

    public boolean isExpired() {
        return Instant.now().isAfter(expiresAt);
    }
}

