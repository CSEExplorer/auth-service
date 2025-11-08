package com.bookify.auth_service.authn.user.jwt.service.producer;


import com.bookify.auth_service.authn.user.jwt.event.EmailEvent;
import lombok.RequiredArgsConstructor;
import org.springframework.kafka.core.KafkaTemplate;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class EmailEventProducer {

    private final KafkaTemplate<String, Object> kafkaTemplate;
    private static final String TOPIC = "user-events";

    public void publishEmailEvent(EmailEvent event) {
        try {
            kafkaTemplate.send(TOPIC, event).get();
            System.out.println("✅ Email event published: " + event.getEventType());
        } catch (Exception e) {
            System.err.println("❌ Kafka send failed: " + e.getMessage());
            e.printStackTrace();
            throw new RuntimeException("Failed to construct kafka producer", e);
        }
    }
}
