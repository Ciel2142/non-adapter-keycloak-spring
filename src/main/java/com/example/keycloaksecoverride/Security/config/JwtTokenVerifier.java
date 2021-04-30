package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.domain.AuthValues;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtTokenVerifier extends OncePerRequestFilter {
    private final KeycloakAdapterAuthValid keycloakAdapterAuthValid;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest,
                                    HttpServletResponse httpServletResponse,
                                    FilterChain filterChain) throws ServletException, IOException {
        String authHeader = httpServletRequest.getHeader("Authorization");

        if (authHeader == null || authHeader.isEmpty() || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        String token = authHeader.replace("Bearer ", "");

        try {
            AuthValues authValues = keycloakAdapterAuthValid.validate(token);

            Authentication authentication = new UsernamePasswordAuthenticationToken(
                    authValues.getUserName(),
                    null,
                    authValues.getRoles()
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }catch (Exception e) {
            throw new IllegalStateException(String.format("Token %s cannot be trusted", token));
        }
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
}