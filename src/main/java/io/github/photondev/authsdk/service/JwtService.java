package io.github.photondev.authsdk.service;

import java.util.Date;
import java.util.stream.Collectors;

import io.github.photondev.authsdk.config.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.extern.slf4j.Slf4j;

@Service
@Slf4j @RequiredArgsConstructor
public class JwtService {
    private final JwtUtil jwtUtil;


    public String generateToken(Authentication authentication) {
        String username = authentication.getName();
        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        Date now = new Date();
        Date expirationDate = new Date(now.getTime() + jwtUtil.getToken_duration());

        return Jwts.builder()
                .setSubject(username)
                .claim("roles", authorities)
                .setIssuedAt(now)
                .setExpiration(expirationDate)
                .setIssuer("your-app")
                .signWith(jwtUtil.getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }




    public boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            final String username = jwtUtil.extractUsername(token);
            return (username.equals(userDetails.getUsername()) &&
                    !isTokenExpired(token));
        } catch (Exception e) {
            log.warn("Validation du token échouée: " + e.getMessage());
            return false;
        }
    }

    public boolean isTokenExpired(String token) {
        try {
            return jwtUtil.extractExpiration(token).before(new Date());
        } catch (Exception e) {
            log.warn("Erreur lors de la vérification d'expiration: {}", e.getMessage());
            return true; // Si on ne peut pas vérifier, considérer comme expiré
        }
    }


}