# 📦 Auth SDK - Guide d'Injection dans un Autre Projet

## 🎯 Résumé rapide

L'**Auth SDK** est un starter Spring Boot qui fournit une authentification JWT prête à l'emploi. Grâce à l'**auto-configuration de Spring Boot**, tous les beans sont automatiquement injectables dans vos projets.

## 📚 Documentation disponible

| Fichier | Description |
|---------|-------------|
| **GUIDE_INTEGRATION.md** | Guide complet d'intégration pas à pas |
| **EXEMPLE_UTILISATION.java** | Exemple complet d'application utilisant le SDK |
| **exemple-application.yml** | Exemple de configuration avec tous les profils |
| **EXEMPLE_TEST.java** | Tests d'intégration démontrant l'injection |

---

## ⚡ Installation en 3 étapes

### 1️⃣ Installer le SDK localement

```bash
cd /home/jules/codenv/spring-boot/auth-sdk
mvn clean install
```

### 2️⃣ Ajouter la dépendance dans votre projet

**pom.xml** de votre projet cible :

```xml
<dependency>
    <groupId>io.github.photondev</groupId>
    <artifactId>auth-sdk</artifactId>
    <version>1.2.0</version>
</dependency>
```

### 3️⃣ Configurer le secret JWT

**application.yml** de votre projet cible :

```yaml
jwt:
  auth:
    secret: votre-cle-secrete-ultra-securisee-256-bits-minimum
```

**C'EST TOUT !** 🎉 Les beans sont maintenant injectables.

---

## 💉 Comment injecter les beans

### ✅ Beans disponibles automatiquement

| Bean | Description |
|------|-------------|
| `JwtAuthProperties` | Configuration des propriétés JWT |
| `JwtTokenProvider` | Service de génération/validation de tokens |
| `TokenBlacklistService` | Service de gestion de la blacklist |
| `JwtAuthenticationFilter` | Filtre d'authentification JWT |
| `TokenBlacklistFilter` | Filtre de vérification de la blacklist |

### 📝 Exemple d'injection

```java
package com.example.monapp.service;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor  // Lombok génère le constructeur
public class AuthService {
    
    // ✅ Injection par constructeur (recommandé)
    private final JwtAuthProperties jwtProperties;
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService blacklistService;
    
    public String login(String username) {
        // Générer un token
        return jwtTokenProvider.generateToken(username);
    }
    
    public void logout(String token) {
        // Blacklister le token
        blacklistService.blacklistToken(token);
    }
    
    public boolean isTokenValid(String token) {
        return jwtTokenProvider.validateToken(token) 
            && !blacklistService.isBlacklisted(token);
    }
}
```

---

## 🔧 Configuration complète

### Configuration minimale

```yaml
jwt:
  auth:
    secret: ma-cle-secrete-256-bits
```

### Configuration complète

```yaml
jwt:
  auth:
    enabled: true                          # Active/désactive JWT (défaut: true)
    secret: ma-cle-secrete-256-bits        # OBLIGATOIRE
    expiration: 86400000                   # 24h en ms (défaut: 86400000)
    header: Authorization                  # Header HTTP (défaut: Authorization)
    prefix: "Bearer "                      # Préfixe du token (défaut: Bearer )
    issuer: mon-app                        # Émetteur (défaut: auth-sdk)
    blacklist-enabled: true                # Active la blacklist (défaut: true)
```

### Configuration par environnement

```yaml
# Dev
spring:
  profiles:
    active: dev
---
spring:
  config:
    activate:
      on-profile: dev
jwt:
  auth:
    secret: dev-secret-not-for-production
    expiration: 86400000  # 24h

---
# Prod
spring:
  config:
    activate:
      on-profile: prod
jwt:
  auth:
    secret: ${JWT_SECRET}  # Variable d'environnement
    expiration: 3600000    # 1h en production
```

---

## 🎮 Utilisation dans un contrôleur

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final JwtTokenProvider jwtTokenProvider;
    private final TokenBlacklistService blacklistService;
    
    @PostMapping("/login")
    public ResponseEntity<TokenResponse> login(@RequestBody LoginRequest request) {
        // Vérifier les credentials (à implémenter)
        String token = jwtTokenProvider.generateToken(request.username());
        return ResponseEntity.ok(new TokenResponse(token));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<Void> logout(@RequestHeader("Authorization") String auth) {
        String token = auth.substring(7); // Retire "Bearer "
        blacklistService.blacklistToken(token);
        return ResponseEntity.ok().build();
    }
    
    @GetMapping("/validate")
    public ResponseEntity<Boolean> validate(@RequestHeader("Authorization") String auth) {
        String token = auth.substring(7);
        boolean valid = jwtTokenProvider.validateToken(token) 
                     && !blacklistService.isBlacklisted(token);
        return ResponseEntity.ok(valid);
    }
}
```

---

## 🔒 Configuration Spring Security

```java
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthFilter;
    private final TokenBlacklistFilter blacklistFilter;
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/**").permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(blacklistFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class)
            .build();
    }
}
```

---

## 🧪 Tests

```java
@SpringBootTest
class AuthServiceTest {
    
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    
    @Autowired
    private TokenBlacklistService blacklistService;
    
    @Test
    void testTokenGeneration() {
        String token = jwtTokenProvider.generateToken("user123");
        assertNotNull(token);
        assertTrue(jwtTokenProvider.validateToken(token));
        assertEquals("user123", jwtTokenProvider.getUsernameFromToken(token));
    }
    
    @Test
    void testBlacklist() {
        String token = jwtTokenProvider.generateToken("user123");
        blacklistService.blacklistToken(token);
        assertTrue(blacklistService.isBlacklisted(token));
    }
}
```

---

## 🚨 Bonnes pratiques

### ✅ À FAIRE

- ✅ Utiliser des variables d'environnement pour le secret en production
- ✅ Générer une clé secrète forte (min 256 bits)
- ✅ Implémenter votre propre `TokenBlacklistService` avec Redis/DB
- ✅ Configurer des expirations courtes en production (1h)
- ✅ Utiliser HTTPS en production
- ✅ Valider et blacklister les tokens lors du logout

### ❌ À ÉVITER

- ❌ Ne JAMAIS commiter le secret dans Git
- ❌ Ne pas utiliser `InMemoryTokenBlacklistService` en production
- ❌ Ne pas réutiliser le même secret entre environnements
- ❌ Ne pas mettre des expirations trop longues (> 24h)

---

## 🔄 Remplacer l'implémentation par défaut

### Exemple : TokenBlacklistService avec Redis

```java
@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistService implements TokenBlacklistService {
    
    private final StringRedisTemplate redisTemplate;
    
    @Override
    public void blacklistToken(String token) {
        redisTemplate.opsForValue().set(
            "blacklist:" + token, 
            "true", 
            24, 
            TimeUnit.HOURS
        );
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(
            redisTemplate.hasKey("blacklist:" + token)
        );
    }
}
```

Spring Boot utilisera automatiquement votre implémentation au lieu de celle par défaut !

---

## 📖 Documentation complète

Consultez les fichiers suivants pour plus de détails :

- **GUIDE_INTEGRATION.md** - Guide complet étape par étape
- **EXEMPLE_UTILISATION.java** - Application complète d'exemple
- **exemple-application.yml** - Configuration avec profils dev/test/prod
- **EXEMPLE_TEST.java** - Tests d'intégration complets

---

## 🆘 Aide et support

### Vérifier que l'auto-configuration fonctionne

Au démarrage, vous devriez voir :

```
🔐 JWT Authentication SDK activé
✅ Configuration JwtTokenProvider
✅ Configuration JwtAuthenticationFilter
✅ Configuration TokenBlacklistFilter
```

### Problèmes courants

**Beans non injectés ?**
- Vérifiez que `jwt.auth.enabled=true` (défaut)
- Vérifiez que la dépendance est bien ajoutée au pom.xml
- Assurez-vous d'avoir fait `mvn clean install` dans le SDK

**Secret non configuré ?**
- Ajoutez `jwt.auth.secret` dans application.yml

**Blacklist ne fonctionne pas ?**
- Vérifiez `jwt.auth.blacklist-enabled=true` (défaut)
- En production, implémentez votre propre `TokenBlacklistService`

---

## 📝 Licence

Ce projet est sous licence MIT.

---

**Fait avec ❤️ par l'équipe PhotonDev**

