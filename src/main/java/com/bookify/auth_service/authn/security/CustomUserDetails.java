package com.bookify.auth_service.authn.security;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;


import com.bookify.auth_service.authn.user.entity.User;

import java.util.Collections;


public record CustomUserDetails(User user) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // Example: return user roles in future if needed
        return Collections.emptyList();
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        // ✅ Use email as the primary username for Spring Security
        return user.getEmail();
    }


    @Override
    public boolean isEnabled() {
        return user.getIsActive();
    }
}
