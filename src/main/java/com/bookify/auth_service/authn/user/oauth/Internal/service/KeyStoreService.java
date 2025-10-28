package com.bookify.auth_service.authn.user.oauth.Internal.service;


import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jose.jwk.JWKSet;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;

@Service
@RequiredArgsConstructor
public class KeyStoreService {

    private final JwkRepository jwkRepository;

    public RSAKey generateAndStoreNewKey() throws Exception {
        // 1. Generate RSA key
        RSAKey newKey = new RSAKeyGenerator(2048)
                .keyID(UUID.randomUUID().toString())
                .generate();

        // 2. Mark all existing keys inactive
        List<JwkEntity> all = jwkRepository.findAll();
        for (JwkEntity k : all) {
            k.setActive(false);
        }
        jwkRepository.saveAll(all);

        // 3. Store new key
        JwkEntity entity = JwkEntity.builder()
                .keyId(newKey.getKeyID())
                .publicKeyJson(newKey.toPublicJWK().toJSONString())
                .privateKeyJson(newKey.toJSONString())
                .active(true)
                .createdAt(Instant.now())
                .build();

        jwkRepository.save(entity);
        return newKey;
    }

    public RSAKey getActiveKey() throws Exception {
        return jwkRepository.findByActiveTrue()
                .map(j -> {
                    try {
                        return RSAKey.parse(j.getPrivateKeyJson());
                    } catch (ParseException e) {
                        throw new RuntimeException(e);
                    }
                })
                .orElseThrow(() -> new IllegalStateException("No active signing key found"));
    }

    public JWKSet getPublicJwks() {
        List<RSAKey> keys = jwkRepository.findAll()
                .stream()
                .map(k -> {
                    try {
                        return RSAKey.parse(k.getPublicKeyJson());
                    } catch (Exception e) {
                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .toList();
        return new JWKSet((JWK) keys);
    }
}

