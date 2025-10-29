package com.bookify.auth_service.authn.user.oauth.Internal.service;



import com.bookify.auth_service.authn.user.oauth.Internal.config.RegisteredClientAdapter;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Authorization;
import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.OAuth2AuthorizationRepository;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.OAuth2ClientRepository;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;


import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Map;
import java.util.Optional;
import java.util.UUID;

@Slf4j
@Service
@RequiredArgsConstructor
public class JpaOAuth2AuthorizationService implements OAuth2AuthorizationService {

    private final OAuth2AuthorizationRepository repository;
    private final RegisteredClientRepository registeredClientRepository;
    private final ObjectMapper objectMapper;
    private final OAuth2ClientRepository oAuth2ClientRepository;
    private final PasswordEncoder passwordEncoder;
    @Override
    @Transactional
    public void save(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        try {
            OAuth2Authorization entity = mapToEntity(authorization);
            repository.save(entity);
        } catch (Exception e) {
            log.error("Error saving authorization", e);
        }
    }

    @Override
    @Transactional
    public void remove(org.springframework.security.oauth2.server.authorization.OAuth2Authorization authorization) {
        if (authorization.getId() != null) {
            repository.deleteById(UUID.fromString(authorization.getId()));
        }
    }

    @Override
    public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findById(String id) {
        return repository.findById(UUID.fromString(id))
                .map(this::mapToObject)
                .orElse(null);
    }

    @Override
    public org.springframework.security.oauth2.server.authorization.OAuth2Authorization findByToken(String token, org.springframework.security.oauth2.server.authorization.OAuth2TokenType tokenType) {
        Optional<OAuth2Authorization> entityOpt = Optional.empty();

        if (tokenType == null || org.springframework.security.oauth2.server.authorization.OAuth2TokenType.ACCESS_TOKEN.equals(tokenType)) {
            entityOpt = repository.findByAccessTokenValue(token);
        } else if (org.springframework.security.oauth2.server.authorization.OAuth2TokenType.REFRESH_TOKEN.equals(tokenType)) {
            entityOpt = repository.findByRefreshTokenValue(token);
        }

        return entityOpt.map(this::mapToObject).orElse(null);
    }

    // ---------- Mapping Helpers ----------

    private OAuth2Authorization mapToEntity(org.springframework.security.oauth2.server.authorization.OAuth2Authorization auth) {
        String clientId = auth.getRegisteredClientId();
        com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client clientEntity =
                oAuth2ClientRepository.findByClientId(clientId)
                        .orElseThrow(() -> new IllegalStateException("Registered client not found in DB"));

        OAuth2Authorization entity = new OAuth2Authorization();
        entity.setRegisteredClient(clientEntity);
        entity.setPrincipalName(auth.getPrincipalName());
        entity.setAuthorizationGrantType(auth.getAuthorizationGrantType().getValue());

        if (auth.getAccessToken() != null) {
            var token = auth.getAccessToken().getToken();
            entity.setAccessTokenValue(token.getTokenValue());
            entity.setAccessTokenIssuedAt(token.getIssuedAt());
            entity.setAccessTokenExpiresAt(token.getExpiresAt());
        }

        if (auth.getRefreshToken() != null) {
            var token = auth.getRefreshToken().getToken();
            entity.setRefreshTokenValue(token.getTokenValue());
            entity.setRefreshTokenIssuedAt(token.getIssuedAt());
            entity.setRefreshTokenExpiresAt(token.getExpiresAt());
        }

        entity.setAttributes(writeJson(auth.getAttributes()));
        return entity;
    }

    private org.springframework.security.oauth2.server.authorization.OAuth2Authorization mapToObject(OAuth2Authorization entity) {
        OAuth2Client clientEntity = oAuth2ClientRepository.findByClientId(
                entity.getRegisteredClient().getClientId()
        ).orElseThrow(() -> new IllegalStateException("Client not found"));
        RegisteredClient registeredClient = RegisteredClientAdapter.toRegisteredClient(clientEntity, passwordEncoder);
        var builder = org.springframework.security.oauth2.server.authorization.OAuth2Authorization.withRegisteredClient(registeredClient)
                .id(entity.getId().toString())
                .principalName(entity.getPrincipalName())
                .authorizationGrantType(new AuthorizationGrantType(entity.getAuthorizationGrantType()))
                .attributes(attrs -> attrs.putAll(readJson(entity.getAttributes())));

        if (entity.getAccessTokenValue() != null) {
            var token = new OAuth2AccessToken(
                    OAuth2AccessToken.TokenType.BEARER,
                    entity.getAccessTokenValue(),
                    entity.getAccessTokenIssuedAt(),
                    entity.getAccessTokenExpiresAt()
            );
            builder.accessToken(token);
        }

        if (entity.getRefreshTokenValue() != null) {
            var token = new OAuth2RefreshToken(
                    entity.getRefreshTokenValue(),
                    entity.getRefreshTokenIssuedAt(),
                    entity.getRefreshTokenExpiresAt()
            );
            builder.refreshToken(token);
        }

        return builder.build();
    }

    private String writeJson(Object obj) {
        try {
            return objectMapper.writeValueAsString(obj);
        } catch (Exception e) {
            return "{}";
        }
    }

    private Map readJson(String json) {
        try {
            return objectMapper.readValue(json, Map.class);
        } catch (Exception e) {
            return Map.of();
        }
    }
}
