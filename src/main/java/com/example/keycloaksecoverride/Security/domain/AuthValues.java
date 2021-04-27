package com.example.keycloaksecoverride.Security.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@AllArgsConstructor
@NoArgsConstructor
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthValues {
    @JsonProperty("preferred_username")
    private String userName;
    @JsonProperty("roles")
    private List<String> roles;
}
