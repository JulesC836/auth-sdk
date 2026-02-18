package com.example.demo;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;

import static org.assertj.core.api.Assertions.*;

/**
 * Tests d'intégration démontrant l'utilisation de l'Auth SDK
 * Ces tests prouvent que l'injection automatique fonctionne correctement
 */
@SpringBootTest
@ActiveProfiles("test")
class AuthSdkIntegrationTest {

    @Autowired
    private JwtAuthProperties jwtProperties;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private TokenBlacklistService tokenBlacklistService;

    @Test
    @DisplayName("Les beans de l'Auth SDK doivent être injectés automatiquement")
    void beansAreAutowired() {
        assertThat(jwtProperties)
                .as("JwtAuthProperties doit être injecté")
                .isNotNull();

        assertThat(jwtTokenProvider)
                .as("JwtTokenProvider doit être injecté")
                .isNotNull();

        assertThat(tokenBlacklistService)
                .as("TokenBlacklistService doit être injecté")
                .isNotNull();
    }

    @Test
    @DisplayName("JwtAuthProperties doit charger la configuration depuis application.yml")
    void propertiesAreLoaded() {
        assertThat(jwtProperties.getSecret())
                .as("La clé secrète doit être configurée")
                .isNotBlank();

        assertThat(jwtProperties.getExpiration())
                .as("L'expiration doit être positive")
                .isPositive();

        assertThat(jwtProperties.getHeader())
                .as("Le header doit être 'Authorization'")
                .isEqualTo("Authorization");

        assertThat(jwtProperties.getPrefix())
                .as("Le préfixe doit être 'Bearer '")
                .isEqualTo("Bearer ");

        assertThat(jwtProperties.isEnabled())
                .as("JWT doit être activé")
                .isTrue();

        assertThat(jwtProperties.isBlacklistEnabled())
                .as("La blacklist doit être activée")
                .isTrue();
    }

    @Test
    @DisplayName("JwtTokenProvider doit générer un token JWT valide")
    void generateTokenWorks() {
        // Given
        String username = "test-user";

        // When
        String token = jwtTokenProvider.generateToken(username);

        // Then
        assertThat(token)
                .as("Le token ne doit pas être null")
                .isNotNull()
                .as("Le token ne doit pas être vide")
                .isNotBlank();
    }

    @Test
    @DisplayName("JwtTokenProvider doit valider un token correctement")
    void validateTokenWorks() {
        // Given
        String username = "test-user";
        String token = jwtTokenProvider.generateToken(username);

        // When
        boolean isValid = jwtTokenProvider.validateToken(token);

        // Then
        assertThat(isValid)
                .as("Le token généré doit être valide")
                .isTrue();
    }

    @Test
    @DisplayName("JwtTokenProvider doit rejeter un token invalide")
    void invalidTokenIsRejected() {
        // Given
        String invalidToken = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.invalid.token";

        // When
        boolean isValid = jwtTokenProvider.validateToken(invalidToken);

        // Then
        assertThat(isValid)
                .as("Un token invalide doit être rejeté")
                .isFalse();
    }

    @Test
    @DisplayName("JwtTokenProvider doit extraire le username d'un token")
    void extractUsernameWorks() {
        // Given
        String expectedUsername = "test-user";
        String token = jwtTokenProvider.generateToken(expectedUsername);

        // When
        String actualUsername = jwtTokenProvider.getUsernameFromToken(token);

        // Then
        assertThat(actualUsername)
                .as("Le username extrait doit correspondre")
                .isEqualTo(expectedUsername);
    }

    @Test
    @DisplayName("TokenBlacklistService doit blacklister un token")
    void blacklistTokenWorks() {
        // Given
        String username = "test-user";
        String token = jwtTokenProvider.generateToken(username);

        // When
        tokenBlacklistService.blacklistToken(token);
        boolean isBlacklisted = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertThat(isBlacklisted)
                .as("Le token doit être dans la blacklist")
                .isTrue();
    }

    @Test
    @DisplayName("Un token non blacklisté ne doit pas être dans la blacklist")
    void nonBlacklistedTokenIsNotBlacklisted() {
        // Given
        String username = "test-user";
        String token = jwtTokenProvider.generateToken(username);

        // When
        boolean isBlacklisted = tokenBlacklistService.isBlacklisted(token);

        // Then
        assertThat(isBlacklisted)
                .as("Un nouveau token ne doit pas être dans la blacklist")
                .isFalse();
    }

    @Test
    @DisplayName("Workflow complet: générer, valider, blacklister")
    void completeWorkflow() {
        // 1. Générer un token
        String username = "john.doe";
        String token = jwtTokenProvider.generateToken(username);

        assertThat(token).isNotBlank();

        // 2. Valider le token
        assertThat(jwtTokenProvider.validateToken(token))
                .as("Le token doit être valide initialement")
                .isTrue();

        // 3. Extraire le username
        String extractedUsername = jwtTokenProvider.getUsernameFromToken(token);
        assertThat(extractedUsername)
                .as("Le username doit être extrait correctement")
                .isEqualTo(username);

        // 4. Vérifier qu'il n'est pas blacklisté
        assertThat(tokenBlacklistService.isBlacklisted(token))
                .as("Le token ne doit pas être blacklisté au départ")
                .isFalse();

        // 5. Blacklister le token (simuler un logout)
        tokenBlacklistService.blacklistToken(token);

        // 6. Vérifier qu'il est maintenant blacklisté
        assertThat(tokenBlacklistService.isBlacklisted(token))
                .as("Le token doit être blacklisté après logout")
                .isTrue();
    }

    @Test
    @DisplayName("Plusieurs utilisateurs peuvent avoir des tokens différents")
    void multipleUsersHaveDifferentTokens() {
        // Given
        String user1 = "alice";
        String user2 = "bob";

        // When
        String token1 = jwtTokenProvider.generateToken(user1);
        String token2 = jwtTokenProvider.generateToken(user2);

        // Then
        assertThat(token1)
                .as("Les tokens de deux utilisateurs doivent être différents")
                .isNotEqualTo(token2);

        assertThat(jwtTokenProvider.getUsernameFromToken(token1))
                .isEqualTo(user1);

        assertThat(jwtTokenProvider.getUsernameFromToken(token2))
                .isEqualTo(user2);
    }
}

