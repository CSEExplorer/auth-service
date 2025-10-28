package com.bookify.auth_service.authn.user.oauth.Internal.repository;



import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface OAuth2ClientRepository extends JpaRepository<OAuth2Client, String> {

    // 🔹 Find a client by its clientId (used in OAuth token endpoint)
    Optional<OAuth2Client> findByClientId(String clientId);

    // 🔹 Check if a clientId already exists (for validation before creating)
    boolean existsByClientId(String clientId);

    // 🔹 Find a client by name (optional, useful for admin UI)
    Optional<OAuth2Client> findByClientName(String clientName);

    // 🔹 Delete a client by clientId (for admin panel deletion)
    void deleteByClientId(String clientId);

    // 🔹 Get all clients (for listing in admin panel)
    List<OAuth2Client> findAll();
}
