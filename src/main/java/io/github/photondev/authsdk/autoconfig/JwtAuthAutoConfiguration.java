package io.github.photondev.authsdk.autoconfig;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.filter.JwtAuthenticationFilter;
import io.github.photondev.authsdk.filter.TokenBlacklistFilter;
import io.github.photondev.authsdk.service.InMemoryTokenBlacklistService;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

/**
 * Auto-configuration for JWT Authentication SDK
 * Activée automatiquement si Spring Security est présent
 */
@Slf4j
@AutoConfiguration
@ConditionalOnClass(EnableWebSecurity.class)
@ConditionalOnProperty(prefix = "jwt.auth", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(JwtAuthProperties.class)
public class JwtAuthAutoConfiguration {

    public JwtAuthAutoConfiguration() {
        log.info("🔐 JWT Authentication SDK activé");
    }

    @Bean
    @ConditionalOnMissingBean
    public JwtTokenProvider jwtTokenProvider(JwtAuthProperties properties) {
        log.info("✅ Configuration JwtTokenProvider");
        return new JwtTokenProvider(properties);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "jwt.auth", name = "blacklist-enabled", havingValue = "true", matchIfMissing = true)
    public TokenBlacklistService tokenBlacklistService() {
        log.warn("⚠️ Utilisation de InMemoryTokenBlacklistService (dev uniquement)");
        return new InMemoryTokenBlacklistService();
    }

    @Bean
    public JwtAuthenticationFilter jwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider,
            JwtAuthProperties properties) {
        log.info("✅ Configuration JwtAuthenticationFilter");
        return new JwtAuthenticationFilter(jwtTokenProvider, properties);
    }

    @Bean
    @ConditionalOnProperty(prefix = "jwt.auth", name = "blacklist-enabled", havingValue = "true", matchIfMissing = true)
    public TokenBlacklistFilter tokenBlacklistFilter(TokenBlacklistService blacklistService,
            JwtAuthProperties properties) {
        log.info("✅ Configuration TokenBlacklistFilter");
        return new TokenBlacklistFilter(blacklistService, properties);
    }
}
