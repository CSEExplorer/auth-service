package com.bookify.auth_service.authn.user.jwt.entity;
import jakarta.persistence.*;
import lombok.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "users") // table name in PostgreSQL
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class User {

    @Id
    @GeneratedValue
    private UUID id;  // Primary key, auto-generated UUID

    @Column(nullable = false, unique = true, length = 50)
    private String username;  // Unique username, max 50 chars

    @Column(nullable = false, unique = true, length = 100)
    private String email;     // Unique email

    @Column(name = "password_hash", nullable = false)
    private String passwordHash;  // Store hashed password

    @Column(name = "is_active", nullable = false)
    private Boolean isActive; // Default active

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private LocalDateTime createdAt;  // Auto timestamp when created

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;  // Auto timestamp when updated
}
