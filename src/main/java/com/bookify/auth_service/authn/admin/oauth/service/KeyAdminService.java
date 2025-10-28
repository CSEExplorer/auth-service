package com.bookify.auth_service.authn.admin.oauth.service;

import com.bookify.auth_service.authn.user.oauth.Internal.service.KeyStoreService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.util.Map;

@Service
@RequiredArgsConstructor
public class KeyAdminService {

    private final KeyStoreService keyStoreService;

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
}
