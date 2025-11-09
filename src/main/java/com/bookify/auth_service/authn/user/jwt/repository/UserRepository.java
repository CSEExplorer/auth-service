package com.bookify.auth_service.authn.user.jwt.repository;



import com.bookify.auth_service.authn.user.jwt.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;


import java.util.Optional;
import java.util.UUID;

@Repository
public interface UserRepository extends JpaRepository<User, UUID> {

    // Find a user by username
    Optional<User> findByUsername(String username);

    // Find a user by email
    Optional<User> findByEmail(String email);

    // ✅ Combined method for login by username OR email
    @Query("""
           SELECT u FROM User u WHERE u.username = :identifier OR u.email = :identifier
           """)
    Optional<User> findByUsernameOrEmail(@Param("identifier") String identifier);
    // Check if a username exists
    boolean existsByUsername(String username);

    // Check if an email exists
    boolean existsByEmail(String email);



}
