package com.bookify.auth_service.authn.user.oauth.Internal.repository;


import com.bookify.auth_service.authn.user.oauth.Internal.entity.RevokedToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.UUID;

@Repository
public interface RevokedTokenRepository extends JpaRepository<RevokedToken, UUID> {

    boolean existsByTokenId(UUID tokenId);
}

