package com.bookify.auth_service.account_recovery.service;


import com.bookify.auth_service.account_recovery.entity.PasswordResetToken;
import com.bookify.auth_service.account_recovery.repository.PasswordResetTokenRepository;
import com.bookify.auth_service.account_recovery.util.TokenGenerator;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Optional;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class PasswordRecoveryService {

    private final PasswordResetTokenRepository tokenRepository;

    private final TokenGenerator tokenGenerator;
    private final RestClient restClient;   // Spring’s modern HTTP client

    @Value("${auth-service.url}")
    private String authServiceUrl;

    @Value("${password.reset.ttl-minutes:15}")
    private long resetTokenTtlMinutes;

    /**
     * Handles POST /account/forgot-password
     */
    @Transactional
    public String initiatePasswordReset(UUID userId, String userEmail) {
        // Remove old tokens for that user
        tokenRepository.deleteByUserId(userId);

        // Generate secure token
        String token = tokenGenerator.generateToken(32);
        Instant expiry = Instant.now().plus(resetTokenTtlMinutes, ChronoUnit.MINUTES);

        // Persist token
        PasswordResetToken resetToken = PasswordResetToken.builder()
                .userId(userId)
                .token(token)
                .expiresAt(expiry)
                .used(false)
                .build();

        tokenRepository.save(resetToken);

        // Build email link

        String resetLink = String.format("https://yourapp.com/reset-password?token=%s", token);
//        the email link just brings the user to a page, not directly to the POST endpoint.
        // Send mail

// Temporarily disable email sending
        System.out.println("🔐 Password Reset Link (for testing): " + resetLink);

// emailService.sendPasswordResetMail(userEmail, resetLink);

//        emailService.sendPasswordResetMail(userEmail, resetLink);
        return token;
    }

    /**
     * Handles POST /account/reset-password
     */
    @Transactional
    public void resetPassword(String token, String newPassword) {
        Optional<PasswordResetToken> optional = tokenRepository.findByToken(token);
        PasswordResetToken resetToken = optional.orElseThrow(
                () -> new IllegalArgumentException("Invalid or expired token"));

        if (resetToken.isExpired() || resetToken.isUsed()) {
            throw new IllegalArgumentException("Token already used or expired");
        }

        // Call Auth Service to actually update the password
        restClient.post()
                .uri(authServiceUrl + "internal/users/{userId}/reset-password", resetToken.getUserId())
                .body(newPassword)
                .retrieve()
                .toBodilessEntity();

        // Mark token as used
        resetToken.setUsed(true);
        tokenRepository.save(resetToken);
    }
}

