package io.github.photondev.authsdk.service;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;

import java.security.Key;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Core JWT token provider for generating and validating JWT tokens.
 * This is the main component of the auth SDK.
 */
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
        } catch (io.jsonwebtoken.security.SignatureException e) {
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
