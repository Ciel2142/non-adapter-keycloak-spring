package com.example.keycloaksecoverride.Security.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
@RequiredArgsConstructor
public class KeycloakSec extends WebSecurityConfigurerAdapter {
    private final KeycloakAdapterAuthValid keycloakAdapterAuthValid;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable().
//                sessionManagement().
//                sessionCreationPolicy(SessionCreationPolicy.STATELESS).
//                and().
        httpBasic().disable().
                addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), failureHandler())).
                addFilterAfter(new JwtTokenVerifier(keycloakAdapterAuthValid), JwtUsernameAndPasswordAuthenticationFilter.class).
                authorizeRequests().
                antMatchers("/", "index", "/css/**", "/js/**", "/static/**", "/js/**", "/img/**", "/json?**").permitAll().
                anyRequest().
                authenticated().
                and().
                formLogin();

    }

    @Bean
    public AuthenticationProvider customAuthManager() {
        return new CustomAuthProvider(keycloakAdapterAuthValid);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder authenticationManagerBuilder) throws Exception {
        authenticationManagerBuilder.authenticationProvider(customAuthManager());
    }

    @Bean
    public AuthenticationFailureHandler failureHandler() {
        return (request, response, exception) -> {
            String username = request.getParameter("username");
            String error = exception.getMessage();
            System.out.println("A failed login attempt with username: "
                    + username + ". Reason: " + error);

            String redirectUrl = request.getContextPath() + "/login?error";
            response.sendRedirect(redirectUrl);
        };
    }

//    @Bean
//    public AuthenticationSuccessHandler authenticationSuccessHandler() {
//        return (request, response, authentication) -> {
//
//        }
//    }
}
