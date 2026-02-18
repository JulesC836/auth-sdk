## 📦 Côté Client - Implémentation

### 1. RedisTokenBlacklistService (dans le client)

```java
package com.votre.app.service;

import com.votrepackage.authsdk.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;

import java.util.concurrent.TimeUnit;

@Service
@RequiredArgsConstructor
@Slf4j
public class RedisTokenBlacklistService implements TokenBlacklistService {
    
    private final RedisTemplate<String, String> redisTemplate;
    private static final String BLACKLIST_PREFIX = "jwt:blacklist:";
    private static final long EXPIRATION_HOURS = 24;
    
    @Override
    public void blacklist(String token) {
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.opsForValue().set(key, "blacklisted", EXPIRATION_HOURS, TimeUnit.HOURS);
        log.info("Token blacklisté dans Redis");
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        String key = BLACKLIST_PREFIX + token;
        return Boolean.TRUE.equals(redisTemplate.hasKey(key));
    }
    
    @Override
    public void remove(String token) {
        String key = BLACKLIST_PREFIX + token;
        redisTemplate.delete(key);
    }
}
```

### 2. AuthenticationFacade (votre Authenticator refactorisé)

```java
package com.votre.app.facade;

import com.votre.app.dto.*;
import com.votre.app.model.User;
import com.votre.app.service.AuthService;
import com.votre.app.service.UserService;
import com.votrepackage.authsdk.service.JwtTokenProvider;
import com.votrepackage.authsdk.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import javax.validation.Valid;
import java.util.Collections;

@Component
@RequiredArgsConstructor
@Slf4j
public class AuthenticationFacade {

    private final JwtTokenProvider jwtTokenProvider;      // ✅ Du SDK
    private final TokenBlacklistService blacklistService;  // ✅ Votre impl Redis
    private final AuthService authService;                 // ✅ Votre service
    private final UserService userService;                 // ✅ Votre service

    public String home() {
        return "Welcome to Authentication Service";
    }

    public UserResponse registerUser(@Valid RegisterRequest request) throws Exception {
        request.setRole("USER");
        User user = authService.signUp(request);
        return userService.toUserResponse(user, null);
    }

    public UserResponse registerAdmin(@Valid RegisterRequest request) throws Exception {
        request.setRole("ADMIN");
        User user = authService.signUp(request);
        
        if (user == null) {
            log.warn("Nom d'utilisateur déjà pris: {}", request.getUsername());
            throw new IllegalArgumentException("Nom d'utilisateur déjà pris");
        }
        
        return userService.toUserResponse(user, null);
    }

    public UserResponse authenticate(@Valid LoginRequest credentials) throws Exception {
        // 1. Authentifier via votre service
        User user = authService.authenticate(credentials);
        
        // 2. Générer le token via le SDK
        String token = jwtTokenProvider.generateToken(
            user.getUsername(),
            Collections.singletonList(user.getRole()),
            Collections.singletonMap("userId", user.getId())
        );
        
        // 3. Retourner la réponse
        return userService.toUserResponse(user, token);
    }

    public AuthValidationResponse validateToken(String authorizationHeader) {
        // Extraire le token
        String token = extractToken(authorizationHeader);
        if (token == null) {
            return null;
        }
        
        // Vérifier blacklist
        if (blacklistService.isBlacklisted(token)) {
            log.warn("Token blacklisté utilisé");
            return null;
        }
        
        // Valider
        if (!jwtTokenProvider.validateToken(token)) {
            return null;
        }
        
        // Extraire les infos
        Long userId = jwtTokenProvider.getClaimFromToken(token, "userId", Long.class);
        String role = jwtTokenProvider.getRolesFromToken(token).get(0);
        
        return new AuthValidationResponse(userId, role);
    }

    public String logout(String authorizationHeader) {
        String token = extractToken(authorizationHeader);
        if (token == null) {
            return "Token invalide";
        }
        
        if (blacklistService.isBlacklisted(token)) {
            return "Session déjà suspendue";
        }
        
        blacklistService.blacklist(token);
        return "Déconnexion réussie";
    }

    private String extractToken(String authorizationHeader) {
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
            return authorizationHeader.substring(7);
        }
        return null;
    }
}
```

### 3. application.yml (dans le client)

```yaml
jwt:
  auth:
    enabled: true
    secret: your-super-secret-key-change-in-production
    expiration: 86400000  # 24 heures
    header: Authorization
    prefix: "Bearer "
    issuer: my-application
    blacklist-enabled: true

spring:
  redis:
    host: localhost
    port: 6379
```

## 📝 Résumé des changements

### ✅ Dans le STARTER (authsdk)
- `JwtTokenProvider` - Génération/validation
- `TokenBlacklistService` - Interface
- `InMemoryTokenBlacklistService` - Impl par défaut
- `JwtAuthenticationFilter` - Filtre Spring Security
- `TokenBlacklistFilter` - Filtre blacklist
- `JwtAuthProperties` - Configuration
- `JwtAuthAutoConfiguration` - Auto-config

### ✅ Dans le CLIENT (votre app)
- `AuthenticationFacade` - Votre Authenticator refactorisé
- `RedisTokenBlacklistService` - Impl Redis
- `AuthService` - Logique métier auth
- `UserService` - Gestion users
- `UserRepository` - Accès données
- Tous les DTOs, models, validations

Voulez-vous que je détaille un aspect spécifique de cette refactorisation ?