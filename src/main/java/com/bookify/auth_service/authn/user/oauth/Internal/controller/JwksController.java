package com.bookify.auth_service.authn.user.oauth.Internal.controller;

import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;
import java.util.Objects;

@RestController
@RequestMapping("/.well-known")
public class JwksController {

    private final JwkRepository jwkRepository;

    public JwksController(JwkRepository jwkRepository) {
        this.jwkRepository = jwkRepository;
    }

    @GetMapping("/jwks.json")
    public ResponseEntity<Map<String, Object>> getJwks() {
        List<JWK> rsaKeys = jwkRepository.findAllByActiveTrueOrRetiredTrue().stream()
                .filter(jwk -> !jwk.isRevoked())
                .map(jwk -> {
                    try {
                        return RSAKey.parse(jwk.getPublicKeyJson());
                    } catch (Exception e) {
                        // Log and skip invalid keys

                        return null;
                    }
                })
                .filter(Objects::nonNull)
                .map(jwk -> (JWK) jwk)
                .toList();

        // Construct JWKS and expose only public keys
        Map<String, Object> jwks = new JWKSet(rsaKeys)
                .toPublicJWKSet()
                .toJSONObject();

        return ResponseEntity.ok(jwks);
    }

}
