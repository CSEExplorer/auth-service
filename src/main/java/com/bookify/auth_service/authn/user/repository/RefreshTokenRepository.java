package com.bookify.auth_service.authn.user.repository;




import com.bookify.auth_service.authn.user.entity.RefreshToken;
import com.bookify.auth_service.authn.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, String> {

    // Find all non-revoked tokens for a user
    List<RefreshToken> findAllByUserAndRevokedFalse(User user);

    // Optional: find token by ID (for rotation tracking)
    Optional<RefreshToken> findById(String id);

    // Optional: find all revoked or expired tokens for cleanup
    List<RefreshToken> findAllByRevokedTrueOrExpiresAtBefore(java.time.Instant now);
}

