package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    public CustomUserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        // Defensive check
        if (usernameOrEmail == null || usernameOrEmail.trim().isEmpty()) {
            throw new UsernameNotFoundException("Username or email cannot be empty");
        }

        String trimmedInput = usernameOrEmail.trim();
        boolean isEmail = trimmedInput.contains("@") && trimmedInput.contains(".");

        User user = isEmail
                ? userRepository.findByEmail(trimmedInput)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User with email " + trimmedInput + " not found"))
                : userRepository.findByUsername(trimmedInput)
                .orElseThrow(() ->
                        new UsernameNotFoundException("User with username " + trimmedInput + " not found"));

        return new CustomUserDetails(user);
    }


}
