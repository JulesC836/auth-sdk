package io.github.photondev.authsdk.config;

import java.io.IOException;
import java.time.Instant;

import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import io.github.photondev.authsdk.service.JwtService;

import io.jsonwebtoken.JwtException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Component
@RequiredArgsConstructor
@Slf4j
public class JwtAuthFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final JwtUtil jwtUtil;
    private final UserDetailsService userDetailsService;
    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            @NonNull HttpServletResponse response,
            @NonNull FilterChain filterChain
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        
        // Si pas de header Authorization, continuer sans authentification
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        try {
            final String jwt = authHeader.substring(7);
            
            // Valider que le JWT n'est pas vide
            if (jwt.trim().isEmpty()) {
                log.warn("Token JWT vide reçu");
                sendUnauthorizedResponse(response, "Token JWT vide");
                return; // IMPORTANT: Ne pas continuer la chaîne
            }

            // Extraire le nom d'utilisateur du token
            final String username = jwtUtil.extractUsername(jwt);
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            if (username != null && !username.trim().isEmpty() && authentication == null) {
                try {
                    UserDetails userDetails = this.userDetailsService.loadUserByUsername(username);
                    
                    // Vérifier si le token est valide
                    if (jwtService.isTokenValid(jwt, userDetails) && 
                        userDetails.isEnabled() && 
                        userDetails.isAccountNonExpired() && 
                        userDetails.isAccountNonLocked()) {
                        
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                                userDetails,
                                null,
                                userDetails.getAuthorities()
                        );
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                        
                        log.debug("Utilisateur authentifié avec succès: {}", username);
                    } else {
                        // Token invalide - rejeter la requête
                        log.warn("Token invalide pour l'utilisateur: {}", username);
                        sendUnauthorizedResponse(response, "Token invalide ou expiré");
                        return; // IMPORTANT: Ne pas continuer la chaîne
                    }
                } catch (UsernameNotFoundException e) {
                    log.warn("Utilisateur non trouvé: {}", username);
                    sendUnauthorizedResponse(response, "Utilisateur non trouvé");
                    return; // IMPORTANT: Ne pas continuer la chaîne
                }
            } else if (username == null || username.trim().isEmpty()) {
                // Username extrait du token est null ou vide
                log.warn("Nom d'utilisateur invalide extrait du token");
                sendUnauthorizedResponse(response, "Token malformé");
                return; // IMPORTANT: Ne pas continuer la chaîne
            }

            filterChain.doFilter(request, response);

        } catch (JwtException e) {
            log.warn("Erreur JWT: {}", e.getMessage());
            sendUnauthorizedResponse(response, "Token JWT invalide: " + e.getMessage());
            return; // IMPORTANT: Ne pas continuer la chaîne
        } catch (Exception e) {
            log.error("Erreur d'authentification: {}", e.getMessage(), e);
            sendUnauthorizedResponse(response, "Erreur d'authentification");
            return; // IMPORTANT: Ne pas continuer la chaîne
        }
    }

    private void sendUnauthorizedResponse(HttpServletResponse response, String message) throws IOException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        response.setContentType("application/json");
        response.setCharacterEncoding("UTF-8");
        
        String jsonResponse = """
            {
                "error": "Unauthorized",
                "message": "%s",
                "status": 401,
                "timestamp": "%s"
            }
            """.formatted(message, Instant.now());
            
        response.getWriter().write(jsonResponse);
        response.getWriter().flush();
    }

    @Override
    protected boolean shouldNotFilter(@NonNull HttpServletRequest request) {
        String path = request.getRequestURI();
        String method = request.getMethod();
        
        // Endpoints publics qui ne nécessitent pas d'authentification
        return (path.equals("/login") && "POST".equals(method)) ||
               (path.equals("/register") && "POST".equals(method)) ||
               path.startsWith("/api/auth/") ||
               path.startsWith("/api/public/") ||
               path.equals("/health") ||
               path.equals("/actuator/health") ||
               path.equals("/error");
    }
}