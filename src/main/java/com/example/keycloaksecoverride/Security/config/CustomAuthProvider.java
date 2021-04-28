package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.domain.AuthValues;
import com.example.keycloaksecoverride.Security.token.CustomSecToken;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.server.ResponseStatusException;

import java.util.stream.Collectors;

@RequiredArgsConstructor
public class CustomAuthProvider implements AuthenticationProvider {
    private final KeycloakAdapterAuthValid keycloakAdapter;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();

        String token = keycloakAdapter.authenticate(userName, password);

        if (token == null) {
            throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Username not found or password is not correct");
        }

        AuthValues values = keycloakAdapter.validate(token);

        if (values == null) {
            throw new ResponseStatusException(HttpStatus.INTERNAL_SERVER_ERROR, "unexpected error on keycloak side");
        }

        return new CustomSecToken(
                userName,
                null,
                values.getRoles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())).collect(Collectors.toList()),
                token
        );
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
