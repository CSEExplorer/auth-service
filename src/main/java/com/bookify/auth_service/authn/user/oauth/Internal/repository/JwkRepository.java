package com.bookify.auth_service.authn.user.oauth.Internal.repository;

import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface JwkRepository extends JpaRepository<JwkEntity, Long> {

    Optional<JwkEntity> findByActiveTrue();

    Optional<JwkEntity> findByKeyId(String keyId);
    List<JwkEntity> findAllByActiveTrueOrRetiredTrue();
}

