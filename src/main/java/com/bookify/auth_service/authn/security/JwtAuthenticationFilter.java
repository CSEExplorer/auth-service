package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.jwt.service.JwtService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;


import com.bookify.auth_service.authn.exception.jwt.JwtTokenExpiredException;
import com.bookify.auth_service.authn.exception.jwt.JwtTokenRevokedException;

import com.bookify.auth_service.authn.user.jwt.service.TokenBlacklistService;


@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;
    private final TokenBlacklistService tokenBlacklistService;
    private final AuthenticationEntryPoint authenticationEntryPoint;


    public JwtAuthenticationFilter(JwtService jwtService,
                                   UserDetailsService userDetailsService,
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
                                    FilterChain filterChain) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        final String jwt = authHeader.substring(7);

        final String username;
        try {
            username = jwtService.extractUsername(jwt); // may throw SignatureException
        } catch (io.jsonwebtoken.security.SignatureException e) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response,
                    new AuthenticationServiceException("New KeyPair mismatch",
                            new io.jsonwebtoken.security.SignatureException("Signature Mismatch ! mayBe new KeyPair")));
            return;
        }
        final String jti = jwtService.extractJti(jwt);
        System.out.println(username);
        System.out.println(jwt);
        System.out.println(jti);

        try {
            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {

                // 1️⃣ Check if token is blacklisted (revoked)
                if (tokenBlacklistService.isBlacklisted(jti)) {
                    authenticationEntryPoint.commence(request, response,
                            new AuthenticationServiceException("Token revoked",
                                    new JwtTokenRevokedException("Token has been revoked")));
                    return;
                }

                // Check if token is valid
                if (!jwtService.isTokenValid(jwt, username)) {
                    authenticationEntryPoint.commence(request, response,
                            new AuthenticationServiceException("Token expired/invalid",
                                    new JwtTokenExpiredException("Token has expired")));
                    return;
                }

                // 3️⃣ Load user details and set authentication
                UserDetails userDetails = userDetailsService.loadUserByUsername(username);
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                authToken.setDetails(new org.springframework.security.web.authentication.WebAuthenticationDetailsSource()
                        .buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }

        }  catch (Exception e) {
            SecurityContextHolder.clearContext();
            authenticationEntryPoint.commence(request, response,
                    new AuthenticationServiceException("JWT processing error", e));
            return;
        }

        filterChain.doFilter(request, response);
    }
}
