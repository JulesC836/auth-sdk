package com.example.auth_test.config;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class JwtProperties {

    @Value("${jwt.auth.secret}")
    private String secretKey;

    @Value("${jwt.auth.expiration}")
    private long expiration;

    @Bean
    JwtAuthProperties jwtAuthProperties(){
        JwtAuthProperties properties = new JwtAuthProperties();
        properties.setSecret(secretKey);
        properties.setExpiration(expiration);
        return properties;
    }
}
