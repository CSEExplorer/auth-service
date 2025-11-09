package com.bookify.auth_service.authn.user.jwt.controller.internal;


import com.bookify.auth_service.authn.user.jwt.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.UUID;

@RestController
@RequestMapping("/internal/users")

public class InternalUserController {

    private final UserService userService;
    InternalUserController(UserService userService){
        this.userService  = userService;
    }

    @PostMapping("/{userId}/reset-password")
    public ResponseEntity<Void> resetPassword(@PathVariable UUID userId,
                                              @RequestBody String newPassword) {
        userService.resetPassword(userId, newPassword);
        return ResponseEntity.noContent().build();
    }
    @GetMapping("/lookup")
    public ResponseEntity<Map<String, Object>> lookupUserByEmail(@RequestParam String email) {
        var userId = userService.findUserIdByEmail(email);
        return ResponseEntity.ok(Map.of("userId", userId));
    }
}

