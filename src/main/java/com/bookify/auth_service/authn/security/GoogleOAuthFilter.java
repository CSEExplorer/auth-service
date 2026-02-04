package com.bookify.auth_service.authn.security;

import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.oauth.external.facade.GoogleOAuthFacade;
import com.bookify.auth_service.authn.security.CustomUserDetails;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseCookie;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.time.Duration;

@Component
public class GoogleOAuthFilter extends OncePerRequestFilter {

    @Value("${app.frontend.base-url}")
    private String frontendBaseUrl;

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

                // 5️⃣ Send JWT token in response (If you have no frontend
//                response.setHeader("Authorization", "Bearer " + result.jwt());
//
//                // Optional: send response body too
//                response.setContentType("application/json");
//                response.getWriter().write("""
//                    {
//                      "message": "Google login successful",
//                      "token": "%s"
//                    }
//                    """.formatted(result.jwt()));
//                return; // stop chain since this endpoint directly returns response

                // 5️⃣ Send JWT as HTTP-only cookie
                ResponseCookie cookie = ResponseCookie.from("accessToken", result.jwt())
                        .httpOnly(true)
                        .secure(false) // true in prod (HTTPS)
                        .path("/")
                        .maxAge(Duration.ofDays(7))
                        .sameSite("Lax")
                        .build();

                response.addHeader(HttpHeaders.SET_COOKIE, cookie.toString());

// 6️⃣ Redirect browser to frontend
                response.sendRedirect(frontendBaseUrl + "/oauth/success");

                return;



            }
        }

        // Continue normal filter chain for other requests
        chain.doFilter(request, response);
    }
}
