package com.bookify.auth_service.authn.user.jwt.dto;

import com.bookify.auth_service.authn.security.CustomUserDetails;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Set;
import java.util.stream.Collectors;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserDto {

    private String id;
    private String username;
    private String email;
    private Set<String> roles;

    public UserDto(CustomUserDetails user) {
    }

    // Convenience factory method
    public static UserDto from(CustomUserDetails user) {
        return UserDto.builder()
                .id(user.getUserId())
                .username(user.getUsername())
                .email(user.getEmail())
                .roles(Set.of(user.getUser().getRole().name()))
                .build();
    }
}
