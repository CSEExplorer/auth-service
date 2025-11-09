package com.bookify.auth_service.authn.security;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;
import java.util.List;


import com.bookify.auth_service.authn.user.jwt.entity.User;


/**
 * @param user ✅ you keep a reference to your entity
 */
public record CustomUserDetails(User user) implements UserDetails {

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole().name()));
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return user.getUsername(); // or user.getUsername()
    }

    @Override
    public boolean isEnabled() {
        return user.getIsActive();
    }

    // ✅ Add any getters you want to access your original user fields later
    public String getUserId() {
        return user.getId().toString();
    }

    public String getEmail() {
        return user.getEmail();
    }

}
