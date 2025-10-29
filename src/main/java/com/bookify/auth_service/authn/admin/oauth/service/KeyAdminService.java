package com.bookify.auth_service.authn.admin.oauth.service;

import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
import com.bookify.auth_service.authn.user.oauth.Internal.service.KeyStoreService;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.text.ParseException;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class KeyAdminService {

    private final KeyStoreService keyStoreService;

    private final JwkRepository jwkRepository;
    public Map<String, Object> rotateKeys() {
        try {
            RSAKey newKey = keyStoreService.generateAndStoreNewKey();
            return Map.of(
                    "message", "Key rotated successfully",
                    "keyId", newKey.getKeyID()
            );
        } catch (Exception e) {
            return Map.of("error", e.getMessage());
        }
    }

    public JWKSet getCurrentPublicKeys() {
        return keyStoreService.getPublicJwks();
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

    @Transactional
    public void revokeKey(String keyId) {
        jwkRepository.findByKeyId(keyId).ifPresent(key -> {
            key.setRevoked(true);
            key.setActive(false);
            key.setRetired(false);
            jwkRepository.save(key);
        });
    }

    @Transactional
    public void activateKey(String keyId) {
        jwkRepository.findByActiveTrue().ifPresent(k -> {
            k.setActive(false);
            k.setRetired(true);
            jwkRepository.save(k);
        });
        jwkRepository.findByKeyId(keyId).ifPresent(key -> {
            key.setActive(true);
            key.setRevoked(false);
            key.setRetired(false);
            jwkRepository.save(key);
        });
    }

}
