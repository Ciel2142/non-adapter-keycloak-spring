package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.domain.AuthValues;
import com.example.keycloaksecoverride.Security.domain.KeyCloakToken;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.*;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

@RequiredArgsConstructor
@Configuration
public class KeycloakAdapterAuthValid {
    private final RestTemplate restTemplate;
    @Value("keycloak.token.url")
    private String tokenUrl;
    @Value("keycloak.userinfo.url")
    private String userinfo;

    protected String authenticate(String username, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", username);
        body.add("password", password);
        body.add("grant_type", "password");
        body.add("client_secret", "dd622848-f8be-4290-806e-a5a186416433");
        body.add("client_id", "kibana-sso");
        String token = null;
        try {
            ResponseEntity<KeyCloakToken> authResponse = restTemplate.exchange(
                    "http://localhost:8080/auth/realms/TestRealm/protocol/openid-connect/token",
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    KeyCloakToken.class
            );

            token = authResponse.getBody().getJwt();
        } catch (Exception e) {
            e.printStackTrace();
        }


        return token;
    }

    protected AuthValues validate(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Bearer " + token);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);


        ResponseEntity<AuthValues> jwtValues = restTemplate.exchange(
                "http://localhost:8080/auth/realms/TestRealm/protocol/openid-connect/userinfo",
                HttpMethod.POST,
                httpEntity,
                AuthValues.class
        );

        if (jwtValues.getStatusCode() != HttpStatus.OK) {
            return null;
        }

        return jwtValues.getBody();
    }
}
