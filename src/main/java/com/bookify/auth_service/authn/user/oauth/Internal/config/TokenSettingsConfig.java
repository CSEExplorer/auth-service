package com.bookify.auth_service.authn.user.oauth.Internal.config;



import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

@Configuration
public class TokenSettingsConfig {

    @Value("${security.oauth2.access-token.ttl:3600}") // default 1 hour
    private long accessTokenTtl;

    @Value("${security.oauth2.refresh-token.ttl:604800}") // default 7 days
    private long refreshTokenTtl;

    @Value("${security.oauth2.reuse-refresh-tokens:true}")
    private boolean reuseRefreshTokens;

    @Bean
    public TokenSettings tokenSettings() {
        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(accessTokenTtl))
                .refreshTokenTimeToLive(Duration.ofSeconds(refreshTokenTtl))
                .reuseRefreshTokens(reuseRefreshTokens)
                .build();
    }
}

