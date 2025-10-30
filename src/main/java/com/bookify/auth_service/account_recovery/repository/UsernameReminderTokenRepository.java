package com.bookify.auth_service.account_recovery.repository;

import com.bookify.auth_service.account_recovery.entity.UsernameReminderToken;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;
import java.util.UUID;

public interface UsernameReminderTokenRepository extends JpaRepository<UsernameReminderToken, UUID> {
    Optional<UsernameReminderToken> findByToken(String token);
}

