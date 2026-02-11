package io.github.photondev.authsdk.config;

import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.util.Date;
import java.util.function.Function;

@Slf4j @Component
public class JwtUtil {


    @Value("${security.jwt.secret-key}")
    private String secret_key;

    @Getter
    @Value("${security.jwt.expiration-time}")
    private long token_duration;

    public String extractUsername(String token) {
        try {
            return extractClaim(token, Claims::getSubject);
        } catch (Exception e) {
            log.error("Erreur lors de l'extraction du nom d'utilisateur: {}", e.getMessage());
            throw new JwtException("Impossible d'extraire le nom d'utilisateur du token", e);
        }
    }

    public String extractRoles(String token) {
        try {
            return extractClaim(token, claims -> claims.get("roles", String.class));
        } catch (Exception e) {
            log.error("Erreur lors de l'extraction du nom d'utilisateur: {}", e.getMessage());
            throw new JwtException("Impossible d'extraire le nom d'utilisateur du token", e);
        }
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        try {
            return Jwts.parserBuilder()
                    .setSigningKey(getSignInKey())
                    .build()
                    .parseClaimsJws(token) // JWS pour les tokens signés
                    .getBody();
        } catch (ExpiredJwtException e) {
            log.warn("Token expiré: {}", e.getMessage());
            throw new JwtException("Token expiré", e);
        } catch (UnsupportedJwtException e) {
            log.warn("Token non supporté: {}", e.getMessage());
            throw new JwtException("Format de token non supporté", e);
        } catch (MalformedJwtException e) {
            log.warn("Token malformé: {}", e.getMessage());
            throw new JwtException("Token malformé", e);
        } catch (SecurityException e) {
            log.warn("Signature du token invalide: {}", e.getMessage());
            throw new JwtException("Signature invalide", e);
        } catch (IllegalArgumentException e) {
            log.warn("Token vide ou null: {}", e.getMessage());
            throw new JwtException("Token vide", e);
        } catch (Exception e) {
            log.error("Erreur lors du parsing du token: {}", e.getMessage());
            throw new JwtException("Erreur de validation du token", e);
        }
    }

     public Key getSignInKey() {
        try {
            byte[] keyBytes = Decoders.BASE64.decode(secret_key);
            return Keys.hmacShaKeyFor(keyBytes);
        } catch (Exception e) {
            log.error("Erreur lors de la création de la clé de signature: {}", e.getMessage());
            throw new IllegalStateException("Clé secrète invalide", e);
        }
    }
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

}
