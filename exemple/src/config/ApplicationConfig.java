package com.example.auth_test.config;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.filter.JwtAuthenticationFilter;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;

@Configuration
public class ApplicationConfig {

    @Bean
    AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager();
    }

    @Bean
    JwtTokenProvider jwtTokenProvider(JwtAuthProperties jwtAuthProperties){
        return new JwtTokenProvider(jwtAuthProperties);
    }

    @Bean
    JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, JwtAuthProperties jwtAuthProperties){
        return new JwtAuthenticationFilter(jwtTokenProvider, jwtAuthProperties);
    }
}
