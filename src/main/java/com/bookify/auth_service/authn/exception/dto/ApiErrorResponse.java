package com.bookify.auth_service.authn.exception.dto;

import lombok.Builder;
import lombok.Getter;

import java.time.Instant;

@Getter
@Builder
public class ApiErrorResponse {
    private boolean success;
    private ApiError error;
    private Instant timestamp;
    private String path;
}
