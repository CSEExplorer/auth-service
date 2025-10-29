//package com.bookify.auth_service.authn.user.oauth.Internal.init;
//
//
//import com.bookify.auth_service.authn.user.oauth.Internal.config.JwksConfig;
//import com.bookify.auth_service.authn.user.oauth.Internal.entity.JwkEntity;
//import com.bookify.auth_service.authn.user.oauth.Internal.repository.JwkRepository;
//import com.nimbusds.jose.jwk.RSAKey;
//import jakarta.annotation.PostConstruct;
//import lombok.RequiredArgsConstructor;
//import org.springframework.stereotype.Component;
//import org.springframework.transaction.annotation.Transactional;
//
//import java.time.Instant;
//import java.time.LocalDateTime;
//@Component
//@RequiredArgsConstructor
//public class JwkInitializer {
//
//    private final JwkRepository jwkRepository;
//
//    @PostConstruct
//    @Transactional
//    public void persistKey() {
//        if (jwkRepository.findByActiveTrue().isEmpty()) {
//            RSAKey rsaKey = JwksConfig.getRsaKey();
//
//            if (rsaKey == null) {
//                throw new IllegalStateException("RSA key is null. Ensure JwksConfig initializes correctly.");
//            }
//
//            JwkEntity entity = JwkEntity.builder()
//                    .keyId(rsaKey.getKeyID())
//                    .publicKeyJson(rsaKey.toPublicJWK().toJSONString())
//                    .privateKeyJson(rsaKey.toJSONString())
//                    .active(true)
//                    .createdAt(Instant.now())
//                    .build();
//
//            jwkRepository.save(entity);
//            System.out.println("✅ RSA JWK persisted successfully.");
//        } else {
//            System.out.println("ℹ️ Existing RSA JWK found — skipping generation.");
//        }
//    }
//}
