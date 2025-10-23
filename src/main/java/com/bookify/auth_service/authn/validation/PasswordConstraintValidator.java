package com.bookify.auth_service.authn.validation;

import jakarta.validation.ConstraintValidator;
import jakarta.validation.ConstraintValidatorContext;



import java.util.ArrayList;
import java.util.List;

public class PasswordConstraintValidator implements ConstraintValidator<ValidPassword, String> {

    @Override
    public boolean isValid(String password, ConstraintValidatorContext context) {
        if (password == null) return false;

        List<String> errors = new ArrayList<>();

        if (password.length() < 6) {
            errors.add("Password must be at least 6 characters long");
        }
        if (!password.matches(".*[A-Z].*")) {
            errors.add("Password must contain at least one uppercase letter");
        }
        if (!password.matches(".*[a-z].*")) {
            errors.add("Password must contain at least one lowercase letter");
        }
        if (!password.matches(".*[0-9].*")) {
            errors.add("Password must contain at least one digit");
        }
        if (!password.matches(".*[!@#$%^&*()=+].*")) {
            errors.add("Password must contain at least one special character (!@#$%^&*()=+)");
        }

        if (!errors.isEmpty()) {
            // Disable default error message
            context.disableDefaultConstraintViolation();
            // Combine all messages into one
            context.buildConstraintViolationWithTemplate(String.join(", ", errors))
                    .addConstraintViolation();
            return false;
        }

        return true;
    }
}
