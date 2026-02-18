package io.github.photondev.authsdk.util;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.util.StringUtils;

/**
 * Utility class for extracting JWT tokens from HTTP requests
 */
public class TokenExtractor {

    /**
     * Extracts JWT token from HTTP request header
     * 
     * @param request The HTTP request
     * @param header  The header name (e.g., "Authorization")
     * @param prefix  The token prefix (e.g., "Bearer ")
     * @return The extracted token, or null if not found
     */
    public static String extract(HttpServletRequest request, String header, String prefix) {
        String bearerToken = request.getHeader(header);
        if (StringUtils.hasText(bearerToken) && bearerToken.startsWith(prefix)) {
            return bearerToken.substring(prefix.length());
        }
        return null;
    }

    /**
     * Extracts JWT token using default Authorization header and Bearer prefix
     * 
     * @param request The HTTP request
     * @return The extracted token, or null if not found
     */
    public static String extract(HttpServletRequest request) {
        return extract(request, "Authorization", "Bearer ");
    }
}
