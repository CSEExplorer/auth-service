package com.bookify.auth_service.authn.user.jwt.service;



import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;

@Service
public class TokenBlacklistService {

    private final RedisTemplate<String, String> redisTemplate;

    public TokenBlacklistService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    /**
     * Blacklist an access token until its expiration
     * @param jti the JWT ID (from 'jti' claim)
     * @param ttl duration until token expires
     */
    public void blacklistToken(String jti, Duration ttl) {
        redisTemplate.opsForValue().set(jti, "BLACKLISTED", ttl);
    }

    /**
     * Check if token is blacklisted
     */
    public boolean isBlacklisted(String jti) {
        return redisTemplate.hasKey(jti);
    }

    /**
     * Remove a token from blacklist (optional)
     */
    public void removeFromBlacklist(String jti) {
        redisTemplate.delete(jti);
    }
}

