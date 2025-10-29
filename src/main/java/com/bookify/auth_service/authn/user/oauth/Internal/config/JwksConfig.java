package com.bookify.auth_service.authn.user.oauth.Internal.config;

import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import lombok.Getter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

@Configuration
public class JwksConfig {

    private final JwkRepository jwkRepository;

    @Getter
    private static RSAKey rsaKey;

    public JwksConfig(JwkRepository jwkRepository) {
        this.jwkRepository = jwkRepository;
    }

    @Bean
    public JWKSource<SecurityContext> jwkSource() {
        // ✅ 1. Try to load existing JWK from DB
        JwkEntity existing = jwkRepository.findByActiveTrue().orElse(null);

        if (existing != null) {
            try {
                rsaKey = RSAKey.parse(existing.getPrivateKeyJson());
                System.out.println("🔐 Loaded existing JWK from database");
            } catch (Exception e) {
                throw new IllegalStateException("❌ Failed to parse stored JWK", e);
            }
        } else {
            // ✅ 2. Generate and persist a new JWK
            rsaKey = generateRsaKey();
            JwkEntity entity = JwkEntity.builder()
                    .keyId(rsaKey.getKeyID())
                    .publicKeyJson(rsaKey.toPublicJWK().toJSONString())
                    .privateKeyJson(rsaKey.toJSONString())
                    .active(true)
                    .createdAt(Instant.now())
                    .build();

            jwkRepository.save(entity);
            System.out.println("✅ New RSA JWK generated and saved.");
        }

        // ✅ 3. Return Immutable JWK Set
        return new ImmutableJWKSet<>(new JWKSet(rsaKey));
    }

    @Bean
    public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
        return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
    }

    // 🔒 Generate a new RSA keypair
    private static RSAKey generateRsaKey() {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(2048);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();
            RSAPublicKey publicKey = (RSAPublicKey) keyPair.getPublic();
            RSAPrivateKey privateKey = (RSAPrivateKey) keyPair.getPrivate();

            return new RSAKey.Builder(publicKey)
                    .privateKey(privateKey)
                    .keyUse(KeyUse.SIGNATURE)
                    .algorithm(JWSAlgorithm.RS256)
                    .keyID(UUID.randomUUID().toString())
                    .build();
        } catch (Exception e) {
            throw new IllegalStateException("Failed to generate RSA key", e);
        }
    }

    // 🔄 Allow safe static access for other beans like JwkInitializer
    public static RSAKey getRsaKey() {
        if (rsaKey == null) {
            rsaKey = generateRsaKey();
        }
        return rsaKey;
    }
}
