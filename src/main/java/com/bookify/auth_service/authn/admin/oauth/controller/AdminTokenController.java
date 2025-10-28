package com.bookify.auth_service.authn.admin.oauth.controller;

import org.springframework.web.bind.annotation.*;
import java.util.Map;

@RestController
@RequestMapping("/admin/tokens")
public class AdminTokenController {

    @GetMapping("/active")
    public Map<String, Object> listActiveTokens() {
        // In real setup: query OAuth2AuthorizationService
        return Map.of("activeTokens", 23);
    }

    @PostMapping("/revoke")
    public Map<String, Object> revokeToken(@RequestParam String token) {
        // Call authorizationService.remove(token)
        return Map.of("status", "revoked", "token", token);
    }
}

