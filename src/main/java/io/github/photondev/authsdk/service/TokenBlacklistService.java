package io.github.photondev.authsdk.service;

/**
 * Interface pour la gestion de la blacklist de tokens.
 * Les applications clientes doivent implémenter cette interface
 * avec leur propre backend (Redis, Database, etc.)
 */
public interface TokenBlacklistService {

    /**
     * Ajoute un token à la blacklist
     * 
     * @param token Le token à blacklister
     */
    void blacklist(String token);

    /**
     * Vérifie si un token est blacklisté
     * 
     * @param token Le token à vérifier
     * @return true si blacklisté, false sinon
     */
    boolean isBlacklisted(String token);

    /**
     * Supprime un token de la blacklist
     * 
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
