package com.bookify.auth_service.authn.utility;

import java.util.Random;

public class UsernameGenerator {

    private static final Random RANDOM = new Random();

    /**
     * Generate a clean, base username from an email.
     * Example: "aditya.saxena@gmail.com" → "aditya.saxena"
     */
    public static String generateBaseFromEmail(String email) {
        if (email == null || !email.contains("@")) {
            return "user" + randomDigits(4);
        }

        String base = email.split("@")[0];
        base = base.toLowerCase().replaceAll("[^a-z0-9._-]", "");

        // trim leading/trailing symbols like . or _
        base = base.replaceAll("^[._-]+|[._-]+$", "");

        if (base.isEmpty()) {
            base = "user" + randomDigits(4);
        }

        return base;
    }

    /**
     * Generate random digits to append if username is already taken.
     */
    public static String randomDigits(int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append(RANDOM.nextInt(10));
        }
        return sb.toString();
    }
}
