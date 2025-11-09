package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.exception.jwt.JwtTokenExpiredException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenRevokedException;
import com.bookify.auth_service.authn.user.jwt.service.JwtService;
import com.bookify.auth_service.authn.user.jwt.service.TokenBlacklistService;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.Objects;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final AuthenticationEntryPoint authenticationEntryPoint;

    public JwtAuthenticationFilter(JwtService jwtService,
                                   CustomUserDetailsService userDetailsService,
                                   TokenBlacklistService tokenBlacklistService,
                                   AuthenticationEntryPoint authenticationEntryPoint) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
        this.tokenBlacklistService = tokenBlacklistService;
        this.authenticationEntryPoint = authenticationEntryPoint;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        System.out.println(authHeader);
        if (!hasBearerToken(authHeader)) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = extractToken(authHeader);

        try {
            processAuthentication(jwt, request);
        } catch (Exception e) {
            e.printStackTrace(); // TEMP for debugging
            System.err.println("🔥 JWT Filter Exception: " + e.getClass().getName() + " - " + e.getMessage());

            handleError(request, response, e);
            return;
        }

        filterChain.doFilter(request, response);
    }

    // ====================================================
    //  HELPER METHODS
    // ====================================================

    private boolean hasBearerToken(String header) {
        return header != null && header.startsWith("Bearer ");
    }

    private String extractToken(String header) {
        return header.substring(7);
    }

    /**
     * Main orchestration for token processing.
     */
    private void processAuthentication(String jwt, HttpServletRequest request) throws Exception {
        final String username = jwtService.extractUsername(jwt);
        final String jti = jwtService.extractJti(jwt);

        if (username == null || SecurityContextHolder.getContext().getAuthentication() != null) {
            return;
        }

        // 1️⃣ Verify blacklist
        if (tokenBlacklistService.isBlacklisted(jti)) {
            throw new JwtTokenRevokedException("Token has been revoked");
        }

        // 2️⃣ Verify expiration / signature
        if (!jwtService.isTokenValid(jwt, username)) {
            throw new JwtTokenExpiredException("Token has expired or is invalid");
        }

        // 3️⃣ Build authorities
        List<SimpleGrantedAuthority> authorities = extractAuthorities(jwt);

        // 4️⃣ Build Authentication and set in context
        setAuthentication(username, authorities, request);
    }

    /**
     * Extracts authorities (roles) from the JWT claims.
     */
    private List<SimpleGrantedAuthority> extractAuthorities(String jwt) {
        try {
            List<String> roles = jwtService.extractClaim(jwt, claims -> {
                Object rolesObj = claims.get("roles");
                if (rolesObj instanceof List<?>) {
                    return ((List<?>) rolesObj).stream()
                            .filter(Objects::nonNull)
                            .map(Object::toString)
                            .toList();
                }
                return List.of();
            });

            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority("ROLE_" + role))
                    .toList();

        } catch (SignatureException e) {
            throw new AuthenticationServiceException("JWT Signature invalid: possible new keypair", e);
        } catch (Exception e) {
            throw new AuthenticationServiceException("Error parsing roles from JWT", e);
        }
    }

    /**
     * Creates an authenticated user context.
     */
    private void setAuthentication(String username,
                                   List<SimpleGrantedAuthority> authorities,
                                   HttpServletRequest request) {

        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
        UsernamePasswordAuthenticationToken authToken =
                new UsernamePasswordAuthenticationToken(userDetails, null, authorities);
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

        SecurityContextHolder.getContext().setAuthentication(authToken);
    }

    /**
     * Centralized error handler to pass exceptions to Spring Security entry point.
     */
    private void handleError(HttpServletRequest request,
                             HttpServletResponse response,
                             Exception exception) throws IOException, ServletException {

        SecurityContextHolder.clearContext();
        authenticationEntryPoint.commence(
                request,
                response,
                new AuthenticationServiceException("JWT processing error", exception)
        );
    }
}
