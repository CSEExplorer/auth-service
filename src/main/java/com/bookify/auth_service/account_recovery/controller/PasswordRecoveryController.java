package com.bookify.auth_service.account_recovery.controller;


import com.bookify.auth_service.account_recovery.dto.ForgotPasswordRequest;
import com.bookify.auth_service.account_recovery.dto.ResetPasswordRequest;
import com.bookify.auth_service.account_recovery.service.AuthServiceClient;
import com.bookify.auth_service.account_recovery.service.PasswordRecoveryService;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;


@RestController
@RequestMapping("/account")
@RequiredArgsConstructor
public class PasswordRecoveryController {

    private final PasswordRecoveryService passwordRecoveryService;
    private final AuthServiceClient authClient;

    @PostMapping("/forgot-password")
    public ResponseEntity<Map<String, String>> forgotPassword(@Valid @RequestBody ForgotPasswordRequest request) {
        var userId = authClient.getUserIdByEmail(request.email());
        System.out.println("Got the UserId from the email Sucessfully");
        System.out.println(userId);
        String token  = passwordRecoveryService.initiatePasswordReset(userId, request.email());
        String resetLink = String.format("http://localhost:8080/account/reset-password?token=%s", token);

        return ResponseEntity.ok(Map.of(
                "message", "Password reset link generated for testing only.",
                "resetToken", token,
                "resetLink", resetLink
        ));
    }

    @PostMapping("/reset-password")
    public ResponseEntity<Map<String, String>> resetPassword(@Valid @RequestBody ResetPasswordRequest request) {
        passwordRecoveryService.resetPassword(request.token(), request.newPassword());
        return ResponseEntity.ok(Map.of("message", "Password has been successfully reset."));
    }


}
