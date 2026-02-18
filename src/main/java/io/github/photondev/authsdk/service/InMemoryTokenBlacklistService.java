package io.github.photondev.authsdk.service;

import lombok.extern.slf4j.Slf4j;

import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Implémentation en mémoire pour dev/test
 * ⚠️ Ne pas utiliser en production (non persisté, non distribué)
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
