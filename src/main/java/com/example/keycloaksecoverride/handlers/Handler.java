package com.example.keycloaksecoverride.handlers;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@Configuration
public class Handler {

    @GetMapping("/")
    public String hello() {
        return "Hello";
    }

    @GetMapping("/test")
    public String helloAuth() {
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getAuthorities());
        System.out.println(SecurityContextHolder.getContext().getAuthentication().getName());
        return "Hello " + SecurityContextHolder.getContext().getAuthentication().getName();
    }
}
