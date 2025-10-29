package com.bookify.auth_service.authn.user.oauth.Internal.config;


import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;

import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

import java.util.UUID;

@Configuration
@EnableWebSecurity
public class AuthorizationServerConfig {

    /**
     * 🧱 Security Filter for all /oauth2/* endpoints (Authorization Server endpoints)
     */
    @Bean
    @Order(0)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
        OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
                OAuth2AuthorizationServerConfigurer.authorizationServer();

        http
                .securityMatcher(authorizationServerConfigurer.getEndpointsMatcher()) // Apply only to /oauth2/**
                .with(authorizationServerConfigurer, (authorizationServer) ->
                        authorizationServer.oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
                )
                .authorizeHttpRequests(auth -> auth.anyRequest().authenticated())
                .exceptionHandling(ex -> ex.defaultAuthenticationEntryPointFor(
                        new LoginUrlAuthenticationEntryPoint("/login"),
                        new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
                ));

        // Add default login page for code flow testing
        http.formLogin(AbstractHttpConfigurer::disable);
        return http.build();
         // for the login page to enable
//        return http.formLogin(Customizer.withDefaults()).build();
    }


    @Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8081") // your auth-service base URL
                .build();
    }
}
