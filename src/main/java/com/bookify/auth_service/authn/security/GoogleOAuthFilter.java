package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.oauth.external.facade.GoogleOAuthFacade;
import com.bookify.auth_service.authn.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
public class GoogleOAuthFilter extends OncePerRequestFilter {

    private final GoogleOAuthFacade googleOAuthFacade;

    public GoogleOAuthFilter(GoogleOAuthFacade googleOAuthFacade) {
        this.googleOAuthFacade = googleOAuthFacade;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain)
            throws ServletException, IOException {

        String path = request.getRequestURI();

        // ✅ Only process Google OAuth callback
        if ("/api/auth/oauth/callback/google".equals(path)) {
            String code = request.getParameter("code");

            if (code != null) {
                // 1️⃣ Handle OAuth flow: exchange code → get Google user → create/find DB user → issue JWT
                GoogleOAuthFacade.OAuthResult result = googleOAuthFacade.handleGoogleOAuthCallback(code);

                // 2️⃣ Wrap your real DB user in CustomUserDetails
                CustomUserDetails userDetails = new CustomUserDetails(result.user());

                // 3️⃣ Create authentication token
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());

                // 4️⃣ Mark this request as authenticated
                SecurityContextHolder.getContext().setAuthentication(authToken);

                // 5️⃣ Send JWT token in response
                response.setHeader("Authorization", "Bearer " + result.jwt());

                // Optional: send response body too
                response.setContentType("application/json");
                response.getWriter().write("""
                    {
                      "message": "Google login successful",
                      "token": "%s"
                    }
                    """.formatted(result.jwt()));
                return; // stop chain since this endpoint directly returns response
            }
        }

        // Continue normal filter chain for other requests
        chain.doFilter(request, response);
    }
}
