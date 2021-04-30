package com.example.keycloaksecoverride.Security.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.List;
import java.util.stream.Collectors;

@AllArgsConstructor
@NoArgsConstructor
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthValues {
    @JsonProperty("preferred_username")
    private String userName;
    @JsonProperty("roles")
    private List<String> roles;

    public List<SimpleGrantedAuthority> getRoles() {
        return getRoles("ROLE_");
    }

    public List<SimpleGrantedAuthority> getRoles(String prefix) {
        return roles.stream().map(v -> new SimpleGrantedAuthority(prefix + v.toUpperCase())).collect(Collectors.toList());
    }
}
