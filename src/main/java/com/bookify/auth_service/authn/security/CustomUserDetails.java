package com.bookify.auth_service.authn.security;


import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import java.util.Collection;

public class CustomUserDetails implements UserDetails {

    private String email;
    private String password;
    private boolean active;

    public CustomUserDetails(String email, String password, boolean active) {
        this.email = email;
        this.password = password;
        this.active = active;
    }


    @Override
    public String getUsername() {
        // You can return email here if you want email to act as username
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return null; // or return roles if you have any
    }



    @Override
    public boolean isEnabled() {
        return active;
    }
}
