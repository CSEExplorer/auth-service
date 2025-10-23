package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.entity.User;
import com.bookify.auth_service.authn.user.repository.BasicUserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class CustomUserDetailsService implements UserDetailsService {

    private final BasicUserRepository basicUserRepository;

    public CustomUserDetailsService(BasicUserRepository basicUserRepository) {
        this.basicUserRepository = basicUserRepository;
    }

    @Override
    public UserDetails loadUserByUsername(String usernameOrEmail) throws UsernameNotFoundException {
        // Check if the input looks like an email
        boolean isEmail = usernameOrEmail.contains("@");

        User user;

        if (isEmail) {
            user = basicUserRepository.findByEmail(usernameOrEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User with email " + usernameOrEmail + " not found"));
        } else {
            user = basicUserRepository.findByUsername(usernameOrEmail)
                    .orElseThrow(() -> new UsernameNotFoundException("User with username " + usernameOrEmail + " not found"));
        }

        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())      // username for Spring Security
                .password(user.getPasswordHash())  // hashed password
                .roles("USER")                     // role(s)
                .build();
    }

}
