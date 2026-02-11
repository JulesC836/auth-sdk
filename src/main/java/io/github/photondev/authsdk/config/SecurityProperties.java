package io.github.photondev.authsdk.config;

import java.util.List;

import org.springframework.boot.context.properties.ConfigurationProperties;

import lombok.Data;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {
//    private List<String> allowedOrigins = List.of("http://localhost:3000", "lb://API-GATEWAY-SERVICE");
    private List<String> publicEndpoints = List.of("/auth/**");
}