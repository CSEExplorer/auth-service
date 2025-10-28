package com.bookify.auth_service.authn.user.oauth.Internal.repository;


import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Authorization;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

@Repository
public interface OAuth2AuthorizationRepository extends JpaRepository<OAuth2Authorization, UUID> {

    Optional<OAuth2Authorization> findByAccessTokenValue(String accessTokenValue);

    Optional<OAuth2Authorization> findByRefreshTokenValue(String refreshTokenValue);

    List<OAuth2Authorization> findByPrincipalName(String principalName);

    List<OAuth2Authorization> findByRegisteredClient_ClientId(String clientId);
}

