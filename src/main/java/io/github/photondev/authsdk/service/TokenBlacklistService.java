package io.github.photondev.authsdk.service;

import java.util.Iterator;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;

import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Slf4j
@RequiredArgsConstructor
@Service
public class TokenBlacklistService {
    private final JwtService jwtService;
    
    // En production, utilisez Redis ou une base de données
    private final Set<String> blacklistedTokens = ConcurrentHashMap.newKeySet();

    // Blacklist a token
    public void blacklistToken(String token) {
        blacklistedTokens.add(token);
    }

    // Vérifie si un token est blacklisté
    public boolean isTokenBlacklisted(String token) {
        if (token!=null) {
            return blacklistedTokens.contains(token);
        }
        return false;
    }

    // Nettoie les tokens expirés de la base de donnée
    @Scheduled(fixedRate = 1, timeUnit = TimeUnit.HOURS)
    public void cleanExpiredTokens() {
        log.info("Cleaning expired tokens...");
        Iterator<String> iterator = blacklistedTokens.iterator();
        while (iterator.hasNext()) {
            String token = iterator.next();
            if (jwtService.isTokenExpired(token)) {
                iterator.remove();
            }
        }
    }
    
    
}
