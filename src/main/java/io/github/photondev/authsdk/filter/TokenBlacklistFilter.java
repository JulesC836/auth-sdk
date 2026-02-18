package io.github.photondev.authsdk.filter;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import io.github.photondev.authsdk.util.TokenExtractor;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

/**
 * Filter that checks if a token is blacklisted and rejects it
 * This filter runs before JwtAuthenticationFilter
 */
@Slf4j
public class TokenBlacklistFilter extends OncePerRequestFilter {

    private final TokenBlacklistService blacklistService;
    private final JwtAuthProperties properties;

    public TokenBlacklistFilter(TokenBlacklistService blacklistService, JwtAuthProperties properties) {
        this.blacklistService = blacklistService;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
            HttpServletResponse response,
            FilterChain filterChain) throws ServletException, IOException {
        String token = TokenExtractor.extract(request, properties.getHeader(), properties.getPrefix());

        if (token != null && blacklistService.isBlacklisted(token)) {
            log.warn("Tentative d'utilisation d'un token blacklisté");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.setContentType("application/json");
            response.getWriter().write("{\"error\": \"Token révoqué\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }
}
