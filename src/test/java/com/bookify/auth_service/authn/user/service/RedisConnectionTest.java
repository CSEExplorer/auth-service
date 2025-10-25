package com.bookify.auth_service.authn.user.service;


import com.bookify.auth_service.authn.user.jwt.service.TokenBlacklistService;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest
public class RedisConnectionTest {

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Test
    void testRedisBlacklist() {
        String testJti = "test-jti-123";

        // 1️⃣ Blacklist the token for 10 seconds
        tokenBlacklistService.blacklistToken(testJti, Duration.ofSeconds(10));

        // 2️⃣ Verify it is blacklisted
        assertTrue(tokenBlacklistService.isBlacklisted(testJti), "Token should be blacklisted");

        // 3️⃣ Wait for 11 seconds (optional, test TTL expiry)
        try {
            Thread.sleep(11000);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        // 4️⃣ After TTL, token should no longer exist
        assertFalse(tokenBlacklistService.isBlacklisted(testJti), "Token should no longer be blacklisted after TTL");
    }
}
