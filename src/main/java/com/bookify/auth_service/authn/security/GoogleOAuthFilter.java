package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.oauth.external.service.GoogleOAuthService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collections;

@Component
public class GoogleOAuthFilter extends OncePerRequestFilter {

    private final GoogleOAuthService googleOAuthService;

    public GoogleOAuthFilter(GoogleOAuthService googleOAuthService) {
        this.googleOAuthService = googleOAuthService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {

        String path = request.getRequestURI();
        System.out.println(path);

        // Only process Google callback
        if ("/api/auth/oauth/callback/google".equals(path)) {
            String code = request.getParameter("code");
            if (code != null) {
                System.out.println(code);
                // Process code using the service and get JWT
                String jwt = googleOAuthService.processOAuthCode(code);
//                System.out.println(jwt);
                // Optionally, set Spring Security Authentication
                User userDetails = new User(googleOAuthService.getUserEmail(), "", Collections.emptyList());
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authToken);

                // Send JWT in response header
                response.setHeader("Authorization", "Bearer " + jwt);
            }
        }

        chain.doFilter(request, response);
    }
}
