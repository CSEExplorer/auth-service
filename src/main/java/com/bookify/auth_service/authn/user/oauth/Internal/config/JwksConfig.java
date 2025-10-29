package com.bookify.auth_service.authn.user.oauth.Internal.config;


import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.jwt.JwtDecoder;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

@Configuration
public class JwksConfig {

    private final JwkRepository jwkRepository;

    public JwksConfig(JwkRepository jwkRepository) {
        this.jwkRepository = jwkRepository;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // 1️⃣ Try to load an active JWK from DB
        var existing = jwkRepository.findByActiveTrue().orElse(null);

        RSAKey rsaKey;

        if (existing != null) {
            // 2️⃣ Parse existing JWK from DB
            try {
                rsaKey = RSAKey.parse(existing.getPrivateKeyJson());
            } catch (Exception e) {
                throw new IllegalStateException("Failed to parse stored JWK", e);
            }
        } else {
            // 3️⃣ Generate new RSA keypair and save it
            KeyPair keyPair = generateRsaKey();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            rsaKey = new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                    .algorithm(com.nimbusds.jose.JWSAlgorithm.RS256)
                    .keyID(UUID.randomUUID().toString())
                    .build();

            // Save new JWK to DB
            JwkEntity entity = JwkEntity.builder()
                    .keyId(rsaKey.getKeyID())
                    .publicKeyJson(rsaKey.toPublicJWK().toJSONString())
                    .privateKeyJson(rsaKey.toJSONString())
                    .active(true)
                    .createdAt(Instant.now())
                    .build();

            jwkRepository.save(entity);
        }

        JWKSet jwkSet = new JWKSet(rsaKey);
        return new ImmutableJWKSet<>(jwkSet);
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    private static KeyPair generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            return keyPairGenerator.generateKeyPair();
        } catch (Exception ex) {
            throw new IllegalStateException(ex);
        }
    }
}


