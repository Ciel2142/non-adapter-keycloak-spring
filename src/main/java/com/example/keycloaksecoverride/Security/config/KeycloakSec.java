package com.example.keycloaksecoverride.Security.config;

import com.example.keycloaksecoverride.Security.filters.JwtTokenVerifier;
import com.example.keycloaksecoverride.Security.filters.JwtUsernameAndPasswordAuthenticationFilter;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class KeycloakSec extends WebSecurityConfigurerAdapter {
    //    private final AuthenticationManager authenticationManager;
    private final KeycloakAdapterAuthValid keycloakAdapterAuthValid;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().
//                sessionManagement().
//                sessionCreationPolicy(SessionCreationPolicy.STATELESS).

                addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager())).
                addFilterAfter(new JwtTokenVerifier(keycloakAdapterAuthValid), JwtUsernameAndPasswordAuthenticationFilter.class).
                authorizeRequests().
                antMatchers("/", "index", "/css/*", "/js/*").permitAll().
                anyRequest().
                authenticated().and().formLogin();

    }


    @Bean
    public CustomAuthManager customAuthManager() {
        return new CustomAuthManager(keycloakAdapterAuthValid);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.authenticationProvider(customAuthManager());
    }
}
