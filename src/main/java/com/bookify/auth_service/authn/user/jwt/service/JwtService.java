package com.bookify.auth_service.authn.user.jwt.service;


import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.user.jwt.entity.RefreshToken;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.repository.RefreshTokenRepository;
import com.bookify.auth_service.authn.user.oauth.Internal.service.KeyStoreService;
import io.jsonwebtoken.*;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;


import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.*;

@Service
public class JwtService {

    private static final PasswordEncoder REFRESH_TOKEN_ENCODER = new BCryptPasswordEncoder();
    private final RefreshTokenRepository refreshTokenRepository;



    private final KeyStoreService keyStoreService;


    public JwtService(
                      RefreshTokenRepository refreshTokenRepository,

                      KeyStoreService keyStoreService) {

        this.refreshTokenRepository = refreshTokenRepository;


        this.keyStoreService = keyStoreService;

    }

    // ================= Access Token =================

    public String generateAccessToken(CustomUserDetails userDetails, List<String> scopes, List<String> roles, String deviceId, String email) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scp", scopes);
        claims.put("roles", roles);
        claims.put("email",email);
        if (deviceId != null) claims.put("device_id", deviceId);

        return createAccessToken(claims, userDetails.getUserId());
    }

    private String createAccessToken(Map<String, Object> claims, String subject) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setId(UUID.randomUUID().toString())      // jti for blacklist
                .setIssuer("auth_service")             // iss
                .setAudience("bookify_service")               // aud
                .setIssuedAt(Date.from(now))
                .setExpiration(Date.from(now.plusMillis(900000L)))
                .signWith(getPrivateKey(), SignatureAlgorithm.RS256)
                .compact();
    }

    // ================= Refresh Token =================

    public String generateRefreshToken(User user) {
        String token = UUID.randomUUID().toString();       // opaque token
        String hash = REFRESH_TOKEN_ENCODER.encode(token);       // store hash only

        // 7 days
        long refreshTokenExpirationMs = 7 * 24 * 60 * 60 * 1000;
        RefreshToken refreshToken = RefreshToken.builder()
                .user(user)
                .tokenHash(hash)
                .createdAt(Instant.now())
                .expiresAt(Instant.now().plusMillis(refreshTokenExpirationMs))
                .revoked(false)
                .build();

        refreshTokenRepository.save(refreshToken);
        return token;
    }

    public String rotateRefreshToken(String oldToken) {
        Optional<RefreshToken> optionalToken = refreshTokenRepository.findAll().stream()
                .filter(t -> REFRESH_TOKEN_ENCODER.matches(oldToken, t.getTokenHash()))
                .findFirst();

        if (optionalToken.isEmpty()) {
            throw new RuntimeException("Refresh token reuse detected or invalid. Re-login required.");
        }

        RefreshToken tokenRecord = optionalToken.get();

        if (tokenRecord.isRevoked() || tokenRecord.getExpiresAt().isBefore(Instant.now())) {
            revokeAllTokensForUser(tokenRecord.getUser());
            throw new RuntimeException("Refresh token expired or revoked. Re-login required.");
        }

        // Mark old token as revoked
        tokenRecord.setRevoked(true);
        refreshTokenRepository.save(tokenRecord);

        // Generate new refresh token
        String newToken = generateRefreshToken(tokenRecord.getUser());
        tokenRecord.setReplacedByToken(newToken);
        refreshTokenRepository.save(tokenRecord);

        return newToken;
    }

    private void revokeAllTokensForUser(User user) {
        List<RefreshToken> tokens = refreshTokenRepository.findAllByUserAndRevokedFalse(user);
        tokens.forEach(t -> t.setRevoked(true));
        refreshTokenRepository.saveAll(tokens);
    }

    // ================= Token Validation =================

    public boolean isAccessTokenValid(String token, UserDetails userDetails) {
        try {
            Claims claims = extractAllClaims(token);
            return claims.getSubject().equals(userDetails.getUsername()) && !isTokenExpired(claims);
        } catch (JwtException e) {
            return false;
        }
    }

    private boolean isTokenExpired(Claims claims) {
        return claims.getExpiration().before(new Date());
    }

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public <T> T extractClaim(String token, java.util.function.Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(getPublicKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // ================= Keys =================

    private PrivateKey getPrivateKey() {
        try {
            var jwk = keyStoreService.getActiveKey();
            return jwk.toRSAPrivateKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load private key", e);
        }
    }

    private PublicKey getPublicKey() {
        try {
            var jwk = keyStoreService.getActiveKey();
            return jwk.toRSAPublicKey();
        } catch (Exception e) {
            throw new RuntimeException("Failed to load public key", e);
        }
    }

    public void revokeAllRefreshTokens(User user) {
        // Find all active (non-revoked) refresh tokens for the user
        List<RefreshToken> activeTokens = refreshTokenRepository.findAllByUserAndRevokedFalse(user);

        // Mark each token as revoked
        activeTokens.forEach(token -> token.setRevoked(true));

        // Save the changes to the database
        refreshTokenRepository.saveAll(activeTokens);
    }

    public boolean isTokenValid(String token, String usernameToCheck) {
        try {
            Claims claims = extractAllClaims(token);          // parse token using public key
            String username = claims.getSubject();           // get "sub" claim
            return username.equals(usernameToCheck) &&       // check username
                    !claims.getExpiration().before(new Date()); // check expiration
        } catch (JwtException | IllegalArgumentException e) {
            // Token is invalid, expired, or tampered
            return false;
        }
    }

    public String extractJti(String token) {
        return extractClaim(token, Claims::getId);
    }
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}