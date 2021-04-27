package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.domain.AuthValues;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.stream.Collectors;

@RequiredArgsConstructor
public class CustomAuthManager implements AuthenticationProvider {
    private final KeycloakAdapterAuthValid keycloakAdapter;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();

        String token = keycloakAdapter.authenticate(userName, password);

        if (token == null) {
            authentication.setAuthenticated(false);
            return authentication;
        }

        AuthValues values = keycloakAdapter.validate(token);

        if (values == null) {
            authentication.setAuthenticated(false);
            return authentication;
        }

        return new UsernamePasswordAuthenticationToken(
                values.getUserName(),
                null,
                values.getRoles().stream().map(role -> new SimpleGrantedAuthority("ROLE_" + role.toUpperCase())).collect(Collectors.toList())
        );
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
