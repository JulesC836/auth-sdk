## 🎯 Architecture Refactorisée

### Starter avec DTOs Optionnels

Si vous voulez fournir des DTOs de base que les clients peuvent utiliser :

```
authsdk/  (STARTER)
├── autoconfigure/
│   └── JwtAuthAutoConfiguration.java
├── config/
│   └── JwtAuthProperties.java
├── service/
│   ├── JwtTokenProvider.java
│   └── TokenBlacklistService.java
├── filter/
│   ├── JwtAuthenticationFilter.java
│   └── TokenBlacklistFilter.java
├── dto/                                   # ✅ DTOs de base (optionnels)
│   ├── BaseLoginRequest.java             # ✅ Classe de base
│   └── BaseAuthResponse.java             # ✅ Classe de base
├── exception/
│   └── JwtAuthenticationException.java
└── example/                               # ✅ Exemples pour documentation
    ├── ExampleAuthController.java
    └── README.md
```

## 🔧 Implémentation du Starter Refactorisé

### 1. JwtTokenProvider (Core du starter)

```java
package com.votrepackage.authsdk.service;

import com.votrepackage.authsdk.config.JwtAuthProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

@Slf4j
public class JwtTokenProvider {

    private final JwtAuthProperties properties;
    private final Key signingKey;

    public JwtTokenProvider(JwtAuthProperties properties) {
        this.properties = properties;
        this.signingKey = Keys.hmacShaKeyFor(properties.getSecret().getBytes());
    }

    /**
     * Génère un token à partir d'une Authentication Spring Security
     */
    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        Collection<String> authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.toList());

        return generateToken(username, authorities, null);
    }

    /**
     * Génère un token avec des claims personnalisés
     */
    public String generateToken(String username, Collection<String> roles, Map<String, Object> additionalClaims) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + properties.getExpiration());

        Map<String, Object> claims = new HashMap<>();
        claims.put("roles", roles);
        if (additionalClaims != null) {
            claims.putAll(additionalClaims);
        }

        return Jwts.builder()
                .setClaims(claims)
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .setIssuer(properties.getIssuer())
                .signWith(signingKey, SignatureAlgorithm.HS512)
                .compact();
    }

    /**
     * Valide un token
     */
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder()
                    .setSigningKey(signingKey)
                    .build()
                    .parseClaimsJws(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.warn("Token expiré: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            log.warn("Token non supporté: {}", e.getMessage());
        } catch (MalformedJwtException e) {
            log.warn("Token malformé: {}", e.getMessage());
        } catch (SignatureException e) {
            log.warn("Signature invalide: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            log.warn("Token vide: {}", e.getMessage());
        }
        return false;
    }

    /**
     * Extrait le username
     */
    public String getUsernameFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getSubject();
    }

    /**
     * Extrait les rôles
     */
    @SuppressWarnings("unchecked")
    public List<String> getRolesFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.get("roles", List.class);
    }

    /**
     * Extrait un claim spécifique
     */
    public <T> T getClaimFromToken(String token, String claimName, Class<T> type) {
        Claims claims = getClaims(token);
        return claims.get(claimName, type);
    }

    /**
     * Extrait tous les claims
     */
    public Claims getClaims(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(signingKey)
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    /**
     * Extrait la date d'expiration
     */
    public Date getExpirationDateFromToken(String token) {
        Claims claims = getClaims(token);
        return claims.getExpiration();
    }
}
```

### 2. TokenBlacklistService (Interface)

```java
package com.votrepackage.authsdk.service;

/**
 * Interface pour la gestion de la blacklist de tokens
 */
public interface TokenBlacklistService {
    
    /**
     * Ajoute un token à la blacklist
     * @param token Le token à blacklister
     */
    void blacklist(String token);
    
    /**
     * Vérifie si un token est blacklisté
     * @param token Le token à vérifier
     * @return true si blacklisté, false sinon
     */
    boolean isBlacklisted(String token);
    
    /**
     * Supprime un token de la blacklist
     * @param token Le token à supprimer
     */
    default void remove(String token) {
        // Implémentation optionnelle
    }
    
    /**
     * Nettoie les tokens expirés de la blacklist
     */
    default void cleanupExpired() {
        // Implémentation optionnelle
    }
}
```

### 3. Implémentation en mémoire (pour dev/test)

```java
package com.votrepackage.authsdk.service;

import lombok.extern.slf4j.Slf4j;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implémentation en mémoire pour dev/test
 * ⚠️ Ne pas utiliser en production
 */
@Slf4j
public class InMemoryTokenBlacklistService implements TokenBlacklistService {
    
    private final Set<String> blacklist = ConcurrentHashMap.newKeySet();
    
    @Override
    public void blacklist(String token) {
        blacklist.add(token);
        log.debug("Token ajouté à la blacklist. Total: {}", blacklist.size());
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        return blacklist.contains(token);
    }
    
    @Override
    public void remove(String token) {
        blacklist.remove(token);
    }
    
    @Override
    public void cleanupExpired() {
        // En mémoire, on peut vider périodiquement
        int size = blacklist.size();
        blacklist.clear();
        log.info("Blacklist nettoyée. {} tokens supprimés", size);
    }
}
```

### 4. JwtAuthenticationFilter

```java
package com.votrepackage.authsdk.filter;

import com.votrepackage.authsdk.config.JwtAuthProperties;
import com.votrepackage.authsdk.service.JwtTokenProvider;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtTokenProvider jwtTokenProvider;
    private final JwtAuthProperties properties;

    public JwtAuthenticationFilter(JwtTokenProvider jwtTokenProvider, JwtAuthProperties properties) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.properties = properties;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {
        try {
            String token = extractTokenFromRequest(request);

            if (token != null && jwtTokenProvider.validateToken(token)) {
                String username = jwtTokenProvider.getUsernameFromToken(token);
                List<String> roles = jwtTokenProvider.getRolesFromToken(token);

                List<SimpleGrantedAuthority> authorities = roles.stream()
                        .map(SimpleGrantedAuthority::new)
                        .collect(Collectors.toList());

                UsernamePasswordAuthenticationToken authentication =
                        new UsernamePasswordAuthenticationToken(username, null, authorities);
                authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));

                SecurityContextHolder.getContext().setAuthentication(authentication);
                
                log.debug("Utilisateur authentifié: {} avec rôles: {}", username, roles);
            }
        } catch (Exception e) {
            log.error("Erreur lors de l'authentification JWT", e);
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(properties.getHeader());
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(properties.getPrefix())) {
            return bearerToken.substring(properties.getPrefix().length());
        }
        return null;
    }
}
```

### 5. TokenBlacklistFilter

```java
package com.votrepackage.authsdk.filter;

import com.votrepackage.authsdk.config.JwtAuthProperties;
import com.votrepackage.authsdk.service.TokenBlacklistService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

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
        String token = extractTokenFromRequest(request);

        if (token != null && blacklistService.isBlacklisted(token)) {
            log.warn("Tentative d'utilisation d'un token blacklisté");
            response.setStatus(HttpStatus.UNAUTHORIZED.value());
            response.getWriter().write("{\"error\": \"Token révoqué\"}");
            return;
        }

        filterChain.doFilter(request, response);
    }

    private String extractTokenFromRequest(HttpServletRequest request) {
        String bearerToken = request.getHeader(properties.getHeader());
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(properties.getPrefix())) {
            return bearerToken.substring(properties.getPrefix().length());
        }
        return null;
    }
}
```

### 6. JwtAuthProperties

```java
package com.votrepackage.authsdk.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
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
```

### 7. Auto-Configuration

```java
package com.votrepackage.authsdk.autoconfigure;

import com.votrepackage.authsdk.config.JwtAuthProperties;
import com.votrepackage.authsdk.filter.JwtAuthenticationFilter;
import com.votrepackage.authsdk.filter.TokenBlacklistFilter;
import com.votrepackage.authsdk.service.InMemoryTokenBlacklistService;
import com.votrepackage.authsdk.service.JwtTokenProvider;
import com.votrepackage.authsdk.service.TokenBlacklistService;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;

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
```

### 8. META-INF pour Spring Boot 3

```
# src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports
com.votrepackage.authsdk.autoconfigure.JwtAuthAutoConfiguration
```

