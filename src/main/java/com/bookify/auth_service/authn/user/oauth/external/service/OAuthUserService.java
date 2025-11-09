package com.bookify.auth_service.authn.user.oauth.external.service;


import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.entity.Role;
import com.bookify.auth_service.authn.user.jwt.repository.UserRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class OAuthUserService {

    private final UserRepository userRepository;

    public OAuthUserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    /**
     * Finds an existing user by email, or creates a new one if not found.
     */
    @Transactional
    public User findOrCreateOAuthUser(String email, String name, String provider) {
        return userRepository.findByEmail(email)
                .orElseGet(() -> {
                    User newUser = User.builder()
                            .username(generateUsername(name, email))
                            .email(email)
                            .passwordHash("") // No password for OAuth
                            .isActive(true)
                            .role(Role.USER)
                            .provider(provider)
                            .build();
                    return userRepository.save(newUser);
                });
    }

    private String generateUsername(String name, String email) {
        // Example: aditya.g or aditya123 if taken
        return name != null ? name.replaceAll("\\s+", "").toLowerCase() :
                email.split("@")[0];
    }
}

