package com.bookify.auth_service.authn.user.jwt.event;


import lombok.*;

import java.util.Map;

@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class EmailEvent {
    private String eventType;
    private String userId;
    private String channel;   // EMAIL, SMS, PUSH
    private String recipient; // email or phone
    private Map<String, Object> data; // dynamic data for template
}

