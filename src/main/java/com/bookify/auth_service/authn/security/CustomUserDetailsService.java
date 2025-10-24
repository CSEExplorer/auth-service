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
        boolean isEmail = usernameOrEmail.contains("@");

        User user = isEmail
                ? basicUserRepository.findByEmail(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User with email " + usernameOrEmail + " not found"))
                : basicUserRepository.findByUsername(usernameOrEmail)
                .orElseThrow(() -> new UsernameNotFoundException("User with username " + usernameOrEmail + " not found"));

        return new CustomUserDetails(user);
    }


}
