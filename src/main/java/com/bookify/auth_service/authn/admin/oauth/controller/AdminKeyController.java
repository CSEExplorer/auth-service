package com.bookify.auth_service.authn.admin.oauth.controller;


import com.bookify.auth_service.authn.admin.oauth.service.KeyAdminService;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/admin/keys")
@RequiredArgsConstructor
public class AdminKeyController {

    private final KeyAdminService keyAdminService;

    @PostMapping("/rotate")
    public ResponseEntity<Map<String, Object>> rotateKeys() {
        return ResponseEntity.ok(keyAdminService.rotateKeys());
    }

    @GetMapping
    public ResponseEntity<Map<String, Object>> getActiveKey() throws Exception {
        RSAKey activeKey = keyAdminService.getActiveKey();

        // Convert the key into a JSON-safe map (only public part)
        Map<String, Object> keyJson = activeKey.toPublicJWK().toJSONObject();

        return ResponseEntity.ok(keyJson);
    }

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> getPublicKeys() {
        JWKSet jwkSet = keyAdminService.getCurrentPublicKeys();
        return ResponseEntity.ok(jwkSet.toJSONObject());
    }

    @PatchMapping("/{keyId}/revoke")
    public ResponseEntity<?> revokeKey(@PathVariable String keyId) {
        keyAdminService.revokeKey(keyId);
        return ResponseEntity.ok(Map.of("message", "Key revoked"));
    }

    @PatchMapping("/{keyId}/activate")
    public ResponseEntity<?> activateKey(@PathVariable String keyId) {
        keyAdminService.activateKey(keyId);
        return ResponseEntity.ok(Map.of("message", "Key activated"));
    }

}


