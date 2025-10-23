package com.bookify.auth_service.authn.user.repository;



import com.bookify.auth_service.authn.user.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;


import java.util.Optional;
import java.util.UUID;

@Repository
public interface BasicUserRepository extends JpaRepository<User, UUID> {

    // Find a user by username
    Optional<User> findByUsername(String username);

    // Find a user by email
    Optional<User> findByEmail(String email);

    // Check if a username exists
    boolean existsByUsername(String username);

    // Check if an email exists
    boolean existsByEmail(String email);


}
