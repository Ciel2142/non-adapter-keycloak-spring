package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.domain.AuthValues;
import com.example.keycloaksecoverride.Security.token.CustomSecToken;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.*;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.web.server.ResponseStatusException;

import javax.security.auth.login.CredentialException;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class CustomAuthProvider implements AuthenticationProvider {
    private final KeycloakAdapterAuthValid keycloakAdapter;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        String userName = authentication.getName();
        String password = authentication.getCredentials().toString();

        System.out.println(password);

        String token = keycloakAdapter.authenticate(userName, password);

        if (token == null) {
            throw new BadCredentialsException("Bad credentials");
        }

        AuthValues values = keycloakAdapter.validate(token);

        if (values == null) {
            throw new AuthenticationServiceException("Authentication service failure");
        }

        return new CustomSecToken(
                userName,
                null,
                values.getRoles(),
                token
        );
    }

    @Override
    public boolean supports(Class<?> aClass) {
        return aClass.equals(UsernamePasswordAuthenticationToken.class);
    }
}
