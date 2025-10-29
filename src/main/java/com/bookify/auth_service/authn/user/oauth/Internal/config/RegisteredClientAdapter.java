package com.bookify.auth_service.authn.user.oauth.Internal.config;


import com.bookify.auth_service.authn.user.oauth.Internal.entity.OAuth2Client;
import com.nimbusds.jose.util.JSONObjectUtils;

import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.text.ParseException;
import java.time.Duration;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Converts between your OAuth2Client entity and Spring Security's RegisteredClient.
 * - Handles redirect_uris, scopes, grant_types stored as JSON array or comma-separated strings.
 * - Does not attempt to parse token_settings JSON into TokenSettings fully; provides sensible defaults.
 */
public final class RegisteredClientAdapter {

    private RegisteredClientAdapter() {

    }

    public static RegisteredClient toRegisteredClient(OAuth2Client entity, PasswordEncoder passwordEncoder) {
        if (entity == null) return null;

        RegisteredClient.Builder builder = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId(entity.getClientId());

        // If clientSecret already seems hashed (starts with $2a$ or $2b$ etc), we store as-is.
        // Otherwise assume it is plain and encode.
        String secret = entity.getClientSecret();
        System.out.println("the client secret is "+secret);
        if (secret != null && (secret.startsWith("$2a$") || secret.startsWith("$2b$") || secret.startsWith("$2y$"))) {
            builder.clientSecret(secret);
        } else if (secret != null && passwordEncoder != null) {
            builder.clientSecret(passwordEncoder.encode(secret));
        } else if (secret != null) {
            builder.clientSecret(secret);
        }

        if (entity.getClientName() != null) {
            builder.clientName(entity.getClientName());
        }

        // Redirect URIs
        parseToCollection(entity.getRedirectUris()).forEach(builder::redirectUri);

        // Grant types
        parseToCollection(entity.getGrantTypes()).stream()
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .forEach(gt -> {
                    // Support common grant type names
                    if ("authorization_code".equalsIgnoreCase(gt) || "auth_code".equalsIgnoreCase(gt)) {
                        builder.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE);
                    } else if ("refresh_token".equalsIgnoreCase(gt)) {
                        builder.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN);
                    } else if ("client_credentials".equalsIgnoreCase(gt)) {
                        builder.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS);
                    } else {
                        // Custom/unknown grant type, add raw
                        builder.authorizationGrantType(new AuthorizationGrantType(gt));
                    }
                });

        // Client authentication method
        if (entity.getClientAuthMethod() != null) {
            String m = entity.getClientAuthMethod();
            if ("client_secret_basic".equalsIgnoreCase(m)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            } else if ("client_secret_post".equalsIgnoreCase(m)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST);
            } else if ("none".equalsIgnoreCase(m) || "public".equalsIgnoreCase(m)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.NONE);
            } else if ("private_key_jwt".equalsIgnoreCase(m)) {
                builder.clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT);
            } else {
                builder.clientAuthenticationMethod(new ClientAuthenticationMethod(m));
            }
        } else {
            // default
            builder.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
        }

        // Scopes
        parseToCollection(entity.getScopes()).forEach(builder::scope);

        // Token settings - try to parse token_settings JSON minimally, else use defaults
        TokenSettings tokenSettings = defaultTokenSettings();
        try {
            tokenSettings = parseTokenSettings(entity.getTokenSettings()).orElse(tokenSettings);
        } catch (Exception ignored) { /* fallback to default */ }
        builder.tokenSettings(tokenSettings);

        // Client settings (requireConsent etc.) - not stored explicitly, use defaults
        builder.clientSettings(ClientSettings.builder().requireAuthorizationConsent(false).build());

        return builder.build();
    }

    public static OAuth2Client toEntity(RegisteredClient client) {
        if (client == null) return null;

        OAuth2Client entity = new OAuth2Client();
        entity.setClientId(client.getClientId());
        entity.setClientSecret(client.getClientSecret());
        entity.setClientName(client.getClientName());

        // redirect URIs -> store as JSON array
        Set<String> redirectUris = client.getRedirectUris();
        entity.setRedirectUris(asJsonArrayString(redirectUris));

        // grant types -> comma separated
        String grants = client.getAuthorizationGrantTypes().stream()
                .map(AuthorizationGrantType::getValue)
                .collect(Collectors.joining(","));
        entity.setGrantTypes(grants);

        // scopes -> comma separated
        String scopes = String.join(",", client.getScopes());
        entity.setScopes(scopes);

        // client auth method -> take first
        if (!client.getClientAuthenticationMethods().isEmpty()) {
            String method = client.getClientAuthenticationMethods().iterator().next().getValue();
            entity.setClientAuthMethod(method);
        }

        // token settings -> store a minimal JSON
        entity.setTokenSettings(tokenSettingsToJson(client.getTokenSettings()));

        // jwks left empty unless client had one
        entity.setJwks(null);

        entity.setActive(true);
        return entity;
    }

    // ----- helpers -----

    private static Collection<String> parseToCollection(String raw) {
        if (raw == null) return Collections.emptyList();
        String trimmed = raw.trim();
        // Try parse as JSON array
        if ((trimmed.startsWith("[") && trimmed.endsWith("]"))) {
            try {
                Object parsed = JSONObjectUtils.parse(trimmed);
                if (parsed instanceof List) {
                    List<?> lst = (List<?>) parsed;
                    return lst.stream().map(Object::toString).collect(Collectors.toList());
                }
            } catch (java.text.ParseException e) {
                // fall through to comma-split
            }
        }
        // comma separated
        return Arrays.stream(raw.split(","))
                .map(String::trim)
                .filter(s -> !s.isEmpty())
                .collect(Collectors.toList());
    }

    private static String asJsonArrayString(Collection<String> items) {
        if (items == null || items.isEmpty()) return "[]";
        StringBuilder sb = new StringBuilder("[");
        String delim = "";
        for (String v : items) {
            sb.append(delim).append("\"").append(escapeJson(v)).append("\"");
            delim = ",";
        }
        sb.append("]");
        return sb.toString();
    }

    private static String escapeJson(String s) {
        return s.replace("\"", "\\\"");
    }

    private static Optional<TokenSettings> parseTokenSettings(String json) {
        // Minimal parsing: if JSON contains access_token_ttl and refresh_token_ttl (ISO-8601 or simple minutes)
        if (json == null || json.isBlank()) return Optional.empty();
        try {
            Map<String, Object> map = JSONObjectUtils.parse(json);
            TokenSettings.Builder b = TokenSettings.builder();
            if (map.containsKey("access_token_ttl")) {
                Object v = map.get("access_token_ttl");
                b.accessTokenTimeToLive(parseDuration(v.toString()));
            }
            if (map.containsKey("refresh_token_ttl")) {
                Object v = map.get("refresh_token_ttl");
                b.refreshTokenTimeToLive(parseDuration(v.toString()));
            }
            return Optional.of(b.build());
        } catch (Exception e) {
            return Optional.empty();
        }
    }

    private static String tokenSettingsToJson(TokenSettings s) {
        if (s == null) return "{}";
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("access_token_ttl", s.getAccessTokenTimeToLive().toString());
        if (s.getRefreshTokenTimeToLive() != null) {
            map.put("refresh_token_ttl", s.getRefreshTokenTimeToLive().toString());
        }
        return mapToJson(map);
    }

    private static String mapToJson(Map<String, Object> map) {
        StringBuilder sb = new StringBuilder("{");
        String delim = "";
        for (Map.Entry<String, Object> e : map.entrySet()) {
            sb.append(delim).append("\"").append(e.getKey()).append("\":");
            sb.append("\"").append(escapeJson(String.valueOf(e.getValue()))).append("\"");
            delim = ",";
        }
        sb.append("}");
        return sb.toString();
    }

    private static Duration parseDuration(String s) {
        // Accept ISO-8601 (PT15M) or simple formats like "15m", "7d"
        if (s == null) return Duration.ofMinutes(15);
        s = s.trim();
        if (s.startsWith("P") || s.startsWith("PT")) {
            return Duration.parse(s);
        }
        // simple suffix parsing
        try {
            if (s.endsWith("ms")) {
                return Duration.ofMillis(Long.parseLong(s.substring(0, s.length() - 2)));
            } else {
                long seconds = Long.parseLong(s.substring(0, s.length() - 1));
                if (s.endsWith("s")) {
                    return Duration.ofSeconds(seconds);
                } else if (s.endsWith("m")) {
                    return Duration.ofMinutes(seconds);
                } else if (s.endsWith("h")) {
                    return Duration.ofHours(seconds);
                } else if (s.endsWith("d")) {
                    return Duration.ofDays(seconds);
                } else {
                    return Duration.ofSeconds(Long.parseLong(s));
                }
            }
        } catch (Exception ex) {
            return Duration.ofMinutes(15);
        }
    }

    private static TokenSettings defaultTokenSettings() {
        TokenSettingsConfig ts = new TokenSettingsConfig();
        return ts.tokenSettings();
    }
}

