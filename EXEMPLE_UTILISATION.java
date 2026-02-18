package com.example.demo;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

/**
 * Exemple d'application démontrant l'utilisation de l'Auth SDK
 */
@SpringBootApplication
public class DemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    /**
     * Bean de démonstration qui s'exécute au démarrage
     */
    @Bean
    public CommandLineRunner demo(DemoService demoService) {
        return args -> {
            System.out.println("\n" + "=".repeat(50));
            System.out.println("🚀 DÉMO AUTH SDK");
            System.out.println("=".repeat(50) + "\n");
            demoService.demonstrateUsage();
        };
    }
}

/**
 * Service de démonstration montrant comment injecter et utiliser les beans
 */
@Slf4j
@Service
@RequiredArgsConstructor
class DemoService {

    // ✅ Injection automatique des beans de l'Auth SDK
    private final JwtAuthProperties jwtProperties;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    public void demonstrateUsage() {
        // 1. Afficher la configuration
        log.info("📋 Configuration JWT:");
        log.info("   - Secret configuré: {}", jwtProperties.getSecret() != null ? "✅ Oui" : "❌ Non");
        log.info("   - Expiration: {} ms ({} heures)",
                 jwtProperties.getExpiration(),
                 jwtProperties.getExpiration() / 3600000);
        log.info("   - Header: {}", jwtProperties.getHeader());
        log.info("   - Prefix: {}", jwtProperties.getPrefix());
        log.info("   - Issuer: {}", jwtProperties.getIssuer());
        log.info("   - JWT activé: {}", jwtProperties.isEnabled());
        log.info("   - Blacklist activée: {}", jwtProperties.isBlacklistEnabled());

        // 2. Générer un token
        log.info("\n🔐 Génération d'un token JWT...");
        String username = "demo-user";
        String token = jwtTokenProvider.generateToken(username);
        log.info("   Token généré: {}", token.substring(0, 50) + "...");

        // 3. Valider le token
        log.info("\n✅ Validation du token...");
        boolean isValid = jwtTokenProvider.validateToken(token);
        log.info("   Token valide: {}", isValid);

        // 4. Extraire le username
        log.info("\n👤 Extraction du username...");
        String extractedUsername = jwtTokenProvider.getUsernameFromToken(token);
        log.info("   Username extrait: {}", extractedUsername);

        // 5. Ajouter à la blacklist
        log.info("\n🚫 Ajout du token à la blacklist...");
        tokenBlacklistService.blacklistToken(token);
        log.info("   Token blacklisté: ✅");

        // 6. Vérifier la blacklist
        log.info("\n🔍 Vérification de la blacklist...");
        boolean isBlacklisted = tokenBlacklistService.isBlacklisted(token);
        log.info("   Token dans la blacklist: {}", isBlacklisted);

        System.out.println("\n" + "=".repeat(50));
        System.out.println("✅ DÉMO TERMINÉE");
        System.out.println("=".repeat(50) + "\n");
    }
}

/**
 * Contrôleur REST d'exemple
 */
@Slf4j
@RestController
@RequestMapping("/api/demo")
@RequiredArgsConstructor
class DemoController {

    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService tokenBlacklistService;

    /**
     * Endpoint pour générer un token
     */
    @PostMapping("/generate-token")
    public TokenResponse generateToken(@RequestBody TokenRequest request) {
        log.info("Génération de token pour: {}", request.username());
        String token = jwtTokenProvider.generateToken(request.username());
        return new TokenResponse(token);
    }

    /**
     * Endpoint pour valider un token
     */
    @PostMapping("/validate-token")
    public ValidationResponse validateToken(@RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        boolean isValid = jwtTokenProvider.validateToken(token);
        boolean isBlacklisted = tokenBlacklistService.isBlacklisted(token);

        String username = null;
        if (isValid && !isBlacklisted) {
            username = jwtTokenProvider.getUsernameFromToken(token);
        }

        return new ValidationResponse(isValid, isBlacklisted, username);
    }

    /**
     * Endpoint pour invalider un token (logout)
     */
    @PostMapping("/logout")
    public LogoutResponse logout(@RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        tokenBlacklistService.blacklistToken(token);
        log.info("Token blacklisté (logout)");
        return new LogoutResponse(true, "Token invalidé avec succès");
    }

    /**
     * Endpoint protégé nécessitant un token valide
     */
    @GetMapping("/protected")
    public ProtectedResponse protectedEndpoint(@RequestHeader("Authorization") String authHeader) {
        String token = extractToken(authHeader);
        String username = jwtTokenProvider.getUsernameFromToken(token);
        return new ProtectedResponse("Accès autorisé pour: " + username);
    }

    private String extractToken(String authHeader) {
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            return authHeader.substring(7);
        }
        throw new IllegalArgumentException("Header Authorization invalide");
    }
}

// DTOs
record TokenRequest(String username) {}
record TokenResponse(String token) {}
record ValidationResponse(boolean valid, boolean blacklisted, String username) {}
record LogoutResponse(boolean success, String message) {}
record ProtectedResponse(String message) {}

