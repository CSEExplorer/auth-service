package com.bookify.auth_service.authn.exception.dto;

import lombok.AllArgsConstructor;
import lombok.Getter;

@Getter
@AllArgsConstructor
public class ApiError {
    private String code;
    private String message;
    private Object details;
}
