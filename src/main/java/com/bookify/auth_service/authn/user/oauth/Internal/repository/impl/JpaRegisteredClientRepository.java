package com.bookify.auth_service.authn.user.oauth.Internal.repository.impl;


import com.bookify.auth_service.authn.user.oauth.Internal.config.RegisteredClientAdapter;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.OAuth2ClientRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Adapter repository implementing Spring Authorization Server's RegisteredClientRepository
 * backed by your OAuth2ClientRepository (DB).
 *
 * Note: save() will persist the RegisteredClient into the oauth2_client table (basic mapping).
 */
@Repository
public class JpaRegisteredClientRepository implements RegisteredClientRepository {

    private final OAuth2ClientRepository clientRepository;
    private final PasswordEncoder passwordEncoder;

    @Autowired
    public JpaRegisteredClientRepository(OAuth2ClientRepository clientRepository,
                                         PasswordEncoder passwordEncoder) {
        this.clientRepository = clientRepository;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void save(RegisteredClient registeredClient) {
        if (registeredClient == null) {
            throw new IllegalArgumentException("registeredClient cannot be null");
        }
        // Convert to entity and persist
        OAuth2Client entity = RegisteredClientAdapter.toEntity(registeredClient);

        // Ensure client secret is encoded
        if (registeredClient.getClientSecret() != null && passwordEncoder != null) {
            // If secret seems raw (not BCrypt), encode
            String raw = registeredClient.getClientSecret();
            if (!(raw.startsWith("$2a$") || raw.startsWith("$2b$") || raw.startsWith("$2y$"))) {
                entity.setClientSecret(passwordEncoder.encode(raw));
            } else {
                entity.setClientSecret(raw);
            }
        }

        clientRepository.save(entity);
    }

    @Override
    public RegisteredClient findById(String id) {
        if (id == null) return null;
        // Our entity uses clientId as PK; RegisteredClient.id (UUID) is not stored.
        // Attempt to find by clientId (id might be clientId in our usage). First look by clientId
        Optional<OAuth2Client> opt = clientRepository.findByClientId(id);
        if (opt.isPresent()) {
            return RegisteredClientAdapter.toRegisteredClient(opt.get(), passwordEncoder);
        }
        // fallback: try by clientName
        opt = clientRepository.findByClientName(id);
        return opt.map(entity -> RegisteredClientAdapter.toRegisteredClient(entity, passwordEncoder)).orElse(null);
    }

    @Override
    public RegisteredClient findByClientId(String clientId) {
        if (clientId == null) return null;
        Optional<OAuth2Client> opt = clientRepository.findByClientId(clientId);
        return opt.map(entity -> RegisteredClientAdapter.toRegisteredClient(entity, passwordEncoder)).orElse(null);
    }

    public List<RegisteredClient> findAll() {
        return clientRepository.findAll()
                .stream()
                .map(entity -> RegisteredClientAdapter.toRegisteredClient(entity, passwordEncoder))
                .collect(Collectors.toList());
    }


}

