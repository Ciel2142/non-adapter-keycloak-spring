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

/**
 * @author Vladislav Lukin
 * */
@RequiredArgsConstructor
@Configuration
public class KeycloakAdapterAuthValid {
    private final RestTemplate restTemplate;
    @Value("${keycloak.token.url}")
    private String tokenUrl;
    @Value("${keycloak.userinfo.url}")
    private String userinfo;
    @Value("${keycloak.client_id}")
    private String keycloakClient;
    @Value("${keycloak.client_secret}")
    private String keycloakClientSecret;

    /**
     * @apiNote method takes credentials and attempts to authenticate using keycloak endpoint if we're successful we return with
     * @return a jwt token which will later on be passed to validate method
     * */
    protected String authenticate(String username, String password) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("username", username);
        body.add("password", password);
        body.add("grant_type", "password");
        body.add("client_secret", keycloakClientSecret);
        body.add("client_id", keycloakClient);

        String token = null;
        try {

            ResponseEntity<KeyCloakToken> authResponse = restTemplate.exchange(
                    tokenUrl,
                    HttpMethod.POST,
                    new HttpEntity<>(body, headers),
                    KeyCloakToken.class
            );

            if (authResponse.getBody() != null) token = authResponse.getBody().getJwt();

        } catch (Exception e) {
            e.printStackTrace();
        }


        return token;
    }

    /**
     * @apiNote method takes jwt token which with which we call keycloak endpoint to parse it, if token is valid it will \
     * @return AuthValues which contains userName and roles */
    protected AuthValues validate(String token) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);
        headers.set("Authorization", "Bearer " + token);
        HttpEntity<String> httpEntity = new HttpEntity<>(headers);


        ResponseEntity<AuthValues> jwtValues = restTemplate.exchange(
                userinfo,
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
