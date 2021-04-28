package com.example.keycloaksecoverride.Security.token;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

public class CustomSecToken extends UsernamePasswordAuthenticationToken {
    private String token;
    public CustomSecToken(Object principal, Object credentials, String token) {
        super(principal, credentials);
        this.token = token;
    }

    public CustomSecToken(Object principal, Object credentials, Collection<? extends GrantedAuthority> authorities, String token) {
        super(principal, credentials, authorities);
        this.token = token;
    }

    public String getToken() {
        String token = this.token;
        this.token = null;
        return token;
    }
}
