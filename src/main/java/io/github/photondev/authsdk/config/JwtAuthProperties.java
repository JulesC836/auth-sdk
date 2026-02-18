package io.github.photondev.authsdk.config;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for JWT authentication
 * Configure via application.yml with prefix jwt.auth
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@ConfigurationProperties(prefix = "jwt.auth")
public class JwtAuthProperties {

    /**
     * Clé secrète pour signer les tokens
     */
    private String secret;

    /**
     * Durée de validité du token en millisecondes (défaut: 24h)
     */
    private long expiration = 86400000L;

    /**
     * Nom du header HTTP contenant le token (défaut: Authorization)
     */
    private String header = "Authorization";

    /**
     * Préfixe du token (défaut: Bearer )
     */
    private String prefix = "Bearer ";

    /**
     * Issuer du token
     */
    private String issuer = "auth-sdk";

    /**
     * Active/désactive l'authentification JWT
     */
    private boolean enabled = true;

    /**
     * Active/désactive la gestion de la blacklist
     */
    private boolean blacklistEnabled = true;
}