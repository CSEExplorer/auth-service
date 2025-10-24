package com.bookify.auth_service.authn.user.service;


import com.bookify.auth_service.authn.user.entity.RefreshToken;
import com.bookify.auth_service.authn.user.entity.User;
import com.bookify.auth_service.authn.user.repository.RefreshTokenRepository;
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

    private final KeyPair keyPair;



    public JwtService(
                      RefreshTokenRepository refreshTokenRepository,

                      KeyPair keyPair) {

        this.refreshTokenRepository = refreshTokenRepository;

        this.keyPair = keyPair;
    }

    // ================= Access Token =================

    public String generateAccessToken(UserDetails userDetails, List<String> scopes, List<String> roles, String deviceId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scp", scopes);
        claims.put("roles", roles);
        if (deviceId != null) claims.put("device_id", deviceId);

        return createAccessToken(claims, userDetails.getUsername());
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
        return keyPair.getPrivate();
    }

    private PublicKey getPublicKey() {
        return keyPair.getPublic();
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










































//
//
//import com.bookify.auth_service.authn.user.entity.JwtToken;
//import com.bookify.auth_service.authn.user.entity.User;
//import com.bookify.auth_service.authn.user.repository.BasicUserRepository;
//import com.bookify.auth_service.authn.user.repository.JwtTokenRepository;
//import io.jsonwebtoken.*;
//import io.jsonwebtoken.io.Decoders;
//import io.jsonwebtoken.security.Keys;
//import org.springframework.beans.factory.annotation.Value;
//
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.stereotype.Service;
//
//import java.security.Key;
//import java.util.Date;
//import java.util.Map;
//import java.util.HashMap;
//import java.util.function.Function;
//
//@Service
//public class JwtService {
//    private final JwtTokenRepository jwtTokenRepository;
//    private final BasicUserRepository userRepository;
//
//    @Value("${jwt.secret}")
//    private String secretKey;
//
//    @Value("${jwt.expiration}")
//    private long jwtExpirationMs;
//
//
//
//
//    private final long accessTokenExpirationMs = 15 * 60 * 1000;
//    // Refresh token 7 days
//    private final long refreshTokenExpirationMs = 7 * 24 * 60 * 60 * 1000;
//
//
//    public JwtService(JwtTokenRepository jwtTokenRepository, BasicUserRepository userRepository) {
//        this.jwtTokenRepository = jwtTokenRepository;
//        this.userRepository = userRepository;
//    }
//
//    public String generateAccessToken(UserDetails userDetails) {
//        return generateToken(userDetails, accessTokenExpirationMs);
//    }
//
//    public String generateRefreshToken(UserDetails userDetails) {
//        return generateToken(userDetails, refreshTokenExpirationMs);
//    }
//
//
//
//    // ✅ Generate token from username or user details
//    private String generateToken(UserDetails userDetails, long expirationMs) {
//        Map<String, Object> claims = new HashMap<>();
//        String token = createToken(claims, userDetails.getUsername(), expirationMs);
//        saveToken(userDetails, token);
//        return token;
//    }
//
//    private String createToken(Map<String, Object> claims, String subject, long expirationMs) {
//        return Jwts.builder()
//                .setClaims(claims)
//                .setSubject(subject)
//                .setIssuedAt(new Date())
//                .setExpiration(new Date(System.currentTimeMillis() + expirationMs))
//                .signWith(getSignKey(), SignatureAlgorithm.HS256)
//                .compact();
//    }
//    private void saveToken(UserDetails userDetails, String token) {
//        User user = userRepository.findByEmail(userDetails.getUsername())
//                .orElseThrow(() -> new RuntimeException("User not found: " + userDetails.getUsername()));
//
//        JwtToken jwtToken = JwtToken.builder()
//                .token(token)
//                .user(user)
//                .revoked(false)
//                .expired(false)
//                .build();
//
//        jwtTokenRepository.save(jwtToken);
//    }
//
//
//
//
//    public void revokeToken(String token) {
//        jwtTokenRepository.findByToken(token).ifPresent(jwtToken -> {
//            jwtToken.setRevoked(true);
//            jwtTokenRepository.save(jwtToken);
//        });
//    }
//
//    // ✅ Extract username from token
//    public String extractUsername(String token) {
//        return extractClaim(token, Claims::getSubject);
//    }
//
//    // ✅ Extract specific claim using a resolver
//    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
//        final Claims claims = extractAllClaims(token);
//        return claimsResolver.apply(claims);
//    }
//
//    // ✅ Validate token with user details
//    public boolean isTokenValid(String token, String userDetails) {
//        final String username = extractUsername(token);
//        return (username.equals(userDetails)) && !isTokenExpired(token);
//    }
//
//    // ✅ Check if expired
//    private boolean isTokenExpired(String token) {
//        return extractExpiration(token).before(new Date());
//    }
//
//    // ✅ Extract expiration
//    private Date extractExpiration(String token) {
//        return extractClaim(token, Claims::getExpiration);
//    }
//
//    // ✅ Parse all claims
//    private Claims extractAllClaims(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(getSignKey())
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//
//    // ✅ Secret key (Base64 encoded in application.yml)
//    private Key getSignKey() {
//        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
//        return Keys.hmacShaKeyFor(keyBytes);
//    }
//}
