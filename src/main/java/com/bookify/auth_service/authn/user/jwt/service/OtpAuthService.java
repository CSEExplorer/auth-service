package com.bookify.auth_service.authn.user.jwt.service;

import com.bookify.auth_service.authn.security.CustomUserDetails;
import com.bookify.auth_service.authn.security.CustomUserDetailsService;
import com.bookify.auth_service.authn.user.jwt.dto.JwtAuthResponse;
import com.bookify.auth_service.authn.user.jwt.dto.OtpVerifyRequest;
import com.bookify.auth_service.authn.user.jwt.entity.User;
import com.bookify.auth_service.authn.user.jwt.event.EmailEvent;
import com.bookify.auth_service.authn.user.jwt.repository.UserRepository;
import com.bookify.auth_service.authn.user.jwt.service.producer.EmailEventProducer;
import lombok.RequiredArgsConstructor;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
public class OtpAuthService {

    private final StringRedisTemplate redisTemplate;
    private final UserRepository userRepository;
    private final JwtService jwtService;
    private final EmailEventProducer emailEventProducer;
    private final CustomUserDetailsService customUserDetailsService;
    private static final int OTP_TTL_MINUTES = 5;

    public void sendOtp(String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new RuntimeException("User not found"));

        String otp = generateOtp();

        String key = "otp:login:" + email;
        redisTemplate.opsForValue().set(
                key,
                otp,
                OTP_TTL_MINUTES,
                TimeUnit.MINUTES
        );

        EmailEvent event = EmailEvent.builder()
                .eventType("LOGIN_OTP")
                .userId(user.getId().toString())
                .channel("EMAIL")
                .recipient(user.getEmail())
                .data(Map.of(
                        "userName", user.getUsername(),
                        "otp", otp,
                        "expiryMinutes", 5
                ))
                .build();

        emailEventProducer.publishEmailEvent(event);
    }

    public JwtAuthResponse verifyOtp(OtpVerifyRequest request) {
        String key = "otp:login:" + request.getEmail();
        String storedOtp = redisTemplate.opsForValue().get(key);

        if (storedOtp == null) {
            throw new RuntimeException("OTP expired or not found");
        }

        if (!storedOtp.equals(request.getOtp())) {
            throw new RuntimeException("Invalid OTP");
        }

        redisTemplate.delete(key); // Important!

        CustomUserDetails userDetails =
                (CustomUserDetails) customUserDetailsService
                        .loadUserByUsername(request.getEmail());


        List<String> scopes = List.of("read", "write");
        List<String> roles = userDetails.getUser().getRole() != null
                ? List.of(userDetails.getUser().getRole().name())
                : List.of();



        String accessToken = jwtService.generateAccessToken(userDetails, scopes, roles, null, request.getEmail(), "OTP");
        String refreshToken = jwtService.generateRefreshToken(userDetails.getUser() , "OTP");

        return new JwtAuthResponse(accessToken, refreshToken);
    }

    private String generateOtp() {
        return String.valueOf(ThreadLocalRandom.current().nextInt(100000, 999999));
    }
}

