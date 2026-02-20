# Guide d'intégration de l'Auth SDK dans un autre projet

## 📦 Étape 1 : Installer le SDK dans votre repository local Maven

Depuis le répertoire racine du projet `auth-sdk`, exécutez :

```bash
mvn clean install
```

Cette commande va :
- Compiler le projet
- Créer le JAR `auth-sdk-1.2.0.jar`
- L'installer dans votre repository Maven local (`~/.m2/repository`)

## 🔧 Étape 2 : Ajouter la dépendance dans le projet cible

Dans le fichier `pom.xml` de votre projet qui va utiliser l'Auth SDK, ajoutez la dépendance :

```xml
<dependencies>
    <!-- Auth SDK -->
    <dependency>
        <groupId>io.github.photondev</groupId>
        <artifactId>auth-sdk</artifactId>
        <version>1.0.0</version>
    </dependency>
    
    <!-- Les dépendances requises (si non déjà présentes) -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-security</artifactId>
    </dependency>
    
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
</dependencies>
```

## ⚙️ Étape 3 : Configurer les propriétés JWT

Dans le fichier `application.yml` (ou `application.properties`) de votre projet cible, ajoutez :

### Format YAML (`application.yml`) :

```yaml
jwt:
  auth:
    enabled: true                          # Active/désactive l'authentification JWT
    secret: votre-cle-secrete-tres-longue  # Clé secrète pour signer les tokens (OBLIGATOIRE)
    expiration: 86400000                    # Durée de validité en millisecondes (24h par défaut)
    header: Authorization                   # Nom du header HTTP (défaut: Authorization)
    prefix: "Bearer "                       # Préfixe du token (défaut: Bearer )
    issuer: mon-application                 # Émetteur du token (défaut: auth-sdk)
    blacklist-enabled: true                 # Active la gestion de la blacklist (défaut: true)
```

### Format Properties (`application.properties`) :

```properties
jwt.auth.enabled=true
jwt.auth.secret=votre-cle-secrete-tres-longue
jwt.auth.expiration=86400000
jwt.auth.header=Authorization
jwt.auth.prefix=Bearer 
jwt.auth.issuer=mon-application
jwt.auth.blacklist-enabled=true
```

## 🚀 Étape 4 : L'auto-configuration fait le reste !

Grâce à Spring Boot Auto-Configuration, les beans suivants seront **automatiquement** créés et injectables :

1. **`JwtAuthProperties`** - Configuration des propriétés JWT
2. **`JwtTokenProvider`** - Service de génération et validation des tokens
3. **`TokenBlacklistService`** - Service de gestion de la blacklist (implémentation en mémoire par défaut)
4. **`JwtAuthenticationFilter`** - Filtre d'authentification JWT
5. **`TokenBlacklistFilter`** - Filtre de vérification de la blacklist

## 💉 Étape 5 : Utiliser les services dans votre code

### Exemple 1 : Injecter `JwtAuthProperties`

```java
package com.example.monprojet.service;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import org.springframework.stereotype.Service;

@Service
public class MonService {
    
    private final JwtAuthProperties jwtProperties;
    
    public MonService(JwtAuthProperties jwtProperties) {
        this.jwtProperties = jwtProperties;
    }
    
    public void afficherConfiguration() {
        System.out.println("Secret: " + jwtProperties.getSecret());
        System.out.println("Expiration: " + jwtProperties.getExpiration());
        System.out.println("Issuer: " + jwtProperties.getIssuer());
        System.out.println("JWT activé: " + jwtProperties.isEnabled());
    }
}
```

### Exemple 2 : Injecter `JwtTokenProvider`

```java
package com.example.monprojet.controller;

import io.github.photondev.authsdk.service.JwtTokenProvider;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {
    
    private final JwtTokenProvider jwtTokenProvider;
    
    public AuthController(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }
    
    @PostMapping("/login")
    public LoginResponse login(@RequestBody LoginRequest request) {
        // Après validation des credentials...
        String token = jwtTokenProvider.generateToken(request.getUsername());
        return new LoginResponse(token);
    }
    
    @GetMapping("/validate")
    public boolean validateToken(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7); // Retire "Bearer "
        return jwtTokenProvider.validateToken(token);
    }
}
```

### Exemple 3 : Injecter `TokenBlacklistService`

```java
package com.example.monprojet.service;

import io.github.photondev.authsdk.service.TokenBlacklistService;
import org.springframework.stereotype.Service;

@Service
public class LogoutService {
    
    private final TokenBlacklistService blacklistService;
    
    public LogoutService(TokenBlacklistService blacklistService) {
        this.blacklistService = blacklistService;
    }
    
    public void logout(String token) {
        blacklistService.blacklistToken(token);
        System.out.println("Token ajouté à la blacklist");
    }
}
```

## 🔒 Étape 6 : Configuration de Spring Security (optionnel)

Si vous voulez personnaliser la configuration de sécurité, créez une classe de configuration :

```java
package com.example.monprojet.config;

import io.github.photondev.authsdk.filter.JwtAuthenticationFilter;
import io.github.photondev.authsdk.filter.TokenBlacklistFilter;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    private final TokenBlacklistFilter tokenBlacklistFilter;
    
    public SecurityConfig(JwtAuthenticationFilter jwtAuthenticationFilter,
                         TokenBlacklistFilter tokenBlacklistFilter) {
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
        this.tokenBlacklistFilter = tokenBlacklistFilter;
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .anyRequest().authenticated()
            )
            .addFilterBefore(tokenBlacklistFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

## 🎛️ Désactiver l'auto-configuration (si nécessaire)

Si vous voulez désactiver complètement l'Auth SDK :

```yaml
jwt:
  auth:
    enabled: false
```

Ou désactiver uniquement la blacklist :

```yaml
jwt:
  auth:
    blacklist-enabled: false
```

## 🔍 Vérifier que l'auto-configuration fonctionne

Au démarrage de votre application, vous devriez voir dans les logs :

```
🔐 JWT Authentication SDK activé
✅ Configuration JwtTokenProvider
⚠️ Utilisation de InMemoryTokenBlacklistService (dev uniquement)
✅ Configuration JwtAuthenticationFilter
✅ Configuration TokenBlacklistFilter
```

## 📝 Configuration minimale requise

**La seule configuration OBLIGATOIRE est la clé secrète** :

```yaml
jwt:
  auth:
    secret: votre-cle-secrete-tres-longue-et-securisee
```

Toutes les autres propriétés ont des valeurs par défaut.

## 🌐 Remplacer l'implémentation par défaut

Vous pouvez fournir votre propre implémentation de `TokenBlacklistService` (par exemple avec Redis) :

```java
package com.example.monprojet.service;

import io.github.photondev.authsdk.service.TokenBlacklistService;
import org.springframework.stereotype.Service;

@Service
public class RedisTokenBlacklistService implements TokenBlacklistService {
    
    // Votre implémentation avec Redis...
    
    @Override
    public void blacklistToken(String token) {
        // Implémentation avec Redis
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        // Implémentation avec Redis
        return false;
    }
}
```

Spring Boot utilisera automatiquement votre implémentation au lieu de `InMemoryTokenBlacklistService`.

## ✅ Résumé

1. ✅ `mvn clean install` dans le projet auth-sdk
2. ✅ Ajouter la dépendance dans le pom.xml du projet cible
3. ✅ Configurer `jwt.auth.secret` dans application.yml
4. ✅ Injecter les beans via constructeur ou @Autowired
5. ✅ Tout fonctionne automatiquement ! 🎉

## 🚨 Attention

- **NE JAMAIS** commiter la clé secrète dans Git
- Utilisez des variables d'environnement ou un gestionnaire de secrets en production
- L'implémentation `InMemoryTokenBlacklistService` n'est pas adaptée à la production (les tokens blacklistés sont perdus au redémarrage)

