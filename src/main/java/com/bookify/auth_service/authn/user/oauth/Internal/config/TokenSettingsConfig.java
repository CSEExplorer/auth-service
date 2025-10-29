package com.bookify.auth_service.authn.user.oauth.Internal.config;



import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.time.Duration;

@Configuration
public class TokenSettingsConfig {

    @Value("${security.oauth2.access-token.ttl:3600}") // default 1 hour
    private Long accessTokenTtl;

    @Value("${security.oauth2.refresh-token.ttl:604800}") // default 7 days
    private Long refreshTokenTtl;

    @Value("${security.oauth2.reuse-refresh-tokens:true}")
    private Boolean reuseRefreshTokens;

    @Bean
    public TokenSettings tokenSettings() {
        long accessTtl = (accessTokenTtl != null) ? accessTokenTtl : 3600L;
        long refreshTtl = (refreshTokenTtl != null) ? refreshTokenTtl : 604800L;
        boolean reuse = (reuseRefreshTokens != null) ? reuseRefreshTokens : true;

        return TokenSettings.builder()
                .accessTokenTimeToLive(Duration.ofSeconds(accessTtl))
                .refreshTokenTimeToLive(Duration.ofSeconds(refreshTtl))
                .reuseRefreshTokens(reuse)
                .build();
    }
}

