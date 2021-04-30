package com.example.keycloaksecoverride;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.web.client.RestTemplate;

@SpringBootApplication
public class SecKeycloakOverrideApplication {

    public static void main(String[] args) {
        SpringApplication.run(SecKeycloakOverrideApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

}
