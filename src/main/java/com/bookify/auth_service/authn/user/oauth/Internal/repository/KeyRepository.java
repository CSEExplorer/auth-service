package com.bookify.auth_service.authn.user.oauth.Internal.repository;

import com.bookify.auth_service.authn.user.oauth.Internal.entity.Key;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;
import java.util.UUID;

@Repository
public interface KeyRepository extends JpaRepository<Key, UUID> {

    Optional<Key> findByKid(String kid);

    Optional<Key> findByActiveTrue();

    boolean existsByActiveTrue();
}

