package com.bookify.auth_service.authn.user.oauth.external.facade;

import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.service.JwtService;
import com.bookify.auth_service.authn.user.oauth.external.service.GoogleOAuthService;

import com.bookify.auth_service.authn.user.oauth.external.service.OAuthUserService;
import org.springframework.stereotype.Service;

@Service
public class GoogleOAuthFacade {

    private final GoogleOAuthService googleOAuthService;
    private final OAuthUserService oAuthUserService;
    private final JwtService jwtService;

    public GoogleOAuthFacade(GoogleOAuthService googleOAuthService,
                             OAuthUserService oAuthUserService,
                             JwtService jwtService) {
        this.googleOAuthService = googleOAuthService;
        this.oAuthUserService = oAuthUserService;
        this.jwtService = jwtService;
    }

    public OAuthResult  handleGoogleOAuthCallback(String code) {
        // 1️⃣ Exchange code for tokens
        var tokens = googleOAuthService.exchangeCodeForToken(code);
        var idToken = tokens.get("id_token");

        // 2️⃣ Extract Google user info
        var googleUser = googleOAuthService.decodeIdToken(idToken);

        // 3️⃣ Find or create our internal user
        User user = oAuthUserService.findOrCreateOAuthUser(
                googleUser.email(),
                googleUser.name(),
                "GOOGLE"
        );

        // 4️⃣ Generate JWT
        CustomUserDetails userDetails = new CustomUserDetails(user);
        String jwt = jwtService.generateAccessToken(userDetails, null, null, null, user.getEmail());
        return new OAuthResult(user, jwt);
     }
    public record OAuthResult(User user, String jwt) {}

}

