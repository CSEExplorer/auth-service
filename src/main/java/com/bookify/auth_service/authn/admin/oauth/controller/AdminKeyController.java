package com.bookify.auth_service.authn.admin.oauth.controller;


import com.bookify.auth_service.authn.admin.oauth.service.KeyAdminService;
import com.nimbusds.jose.jwk.JWKSet;
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

    @GetMapping("/jwks")
    public ResponseEntity<Map<String, Object>> getPublicKeys() {
        JWKSet jwkSet = keyAdminService.getCurrentPublicKeys();
        return ResponseEntity.ok(jwkSet.toJSONObject());
    }
}


