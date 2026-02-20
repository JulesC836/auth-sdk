package com.example.auth_test.config;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.filter.JwtAuthenticationFilter;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthFilter;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http){
        http
            .csrf(AbstractHttpConfigurer::disable)
            .authorizeHttpRequests((auth) ->
                auth.requestMatchers("/api/auth/register", "/api/auth/login").permitAll()
                    .anyRequest().authenticated()
            ).addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return  http.build();
    }


}
