package io.github.photondev.authsdk.service;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtTokenProviderTest {

    private JwtTokenProvider tokenProvider;
    private JwtAuthProperties properties;

    @BeforeEach
    void setUp() {
        properties = new JwtAuthProperties();
        properties.setSecret("this-is-a-very-long-secret-key-with-at-least-256-bits-of-entropy-for-testing");
        properties.setExpiration(3600000); // 1 hour
        properties.setIssuer("test-issuer");
        tokenProvider = new JwtTokenProvider(properties);
    }

    @Test
    void shouldThrowExceptionWhenSecretTooShort() {
        JwtAuthProperties badProps = new JwtAuthProperties();
        badProps.setSecret("short");

        IllegalArgumentException exception = assertThrows(
            IllegalArgumentException.class,
            () -> new JwtTokenProvider(badProps)
        );

        assertTrue(exception.getMessage().contains("256 bits"));
    }

    @Test
    void shouldGenerateValidToken() {
        String token = tokenProvider.generateToken("user123", Arrays.asList("ADMIN", "USER"), null);

        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));
    }

    @Test
    void shouldGenerateTokenWithCustomClaims() {
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("userId", 999L);
        customClaims.put("email", "test@example.com");

        String token = tokenProvider.generateToken("user123", Arrays.asList("USER"), customClaims);

        assertNotNull(token);
        assertTrue(tokenProvider.validateToken(token));

        Long userId = tokenProvider.getClaimFromToken(token, "userId", Long.class);
        String email = tokenProvider.getClaimFromToken(token, "email", String.class);

        assertEquals(999L, userId);
        assertEquals("test@example.com", email);
    }

    @Test
    void shouldExtractUsernameFromToken() {
        String token = tokenProvider.generateToken("testuser", Arrays.asList("USER"), null);

        String username = tokenProvider.getUsernameFromToken(token);

        assertEquals("testuser", username);
    }

    @Test
    void shouldExtractRolesFromToken() {
        List<String> expectedRoles = Arrays.asList("ADMIN", "MODERATOR", "USER");
        String token = tokenProvider.generateToken("user123", expectedRoles, null);

        List<String> roles = tokenProvider.getRolesFromToken(token);

        assertEquals(expectedRoles, roles);
    }

    @Test
    void shouldExtractSpecificClaimFromToken() {
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("department", "Engineering");
        customClaims.put("level", 5);

        String token = tokenProvider.generateToken("user123", Arrays.asList("USER"), customClaims);

        String department = tokenProvider.getClaimFromToken(token, "department", String.class);
        Integer level = tokenProvider.getClaimFromToken(token, "level", Integer.class);

        assertEquals("Engineering", department);
        assertEquals(5, level);
    }

    @Test
    void shouldGetAllClaims() {
        Map<String, Object> customClaims = new HashMap<>();
        customClaims.put("userId", 123L);

        String token = tokenProvider.generateToken("user123", Arrays.asList("USER"), customClaims);

        Claims claims = tokenProvider.getClaims(token);

        assertEquals("user123", claims.getSubject());
        assertEquals("test-issuer", claims.getIssuer());
        assertNotNull(claims.getIssuedAt());
        assertNotNull(claims.getExpiration());
    }

    @Test
    void shouldGetExpirationDate() {
        String token = tokenProvider.generateToken("user123", Arrays.asList("USER"), null);

        Date expirationDate = tokenProvider.getExpirationDateFromToken(token);

        assertNotNull(expirationDate);
        assertTrue(expirationDate.after(new Date()));
    }

    @Test
    void shouldRejectMalformedToken() {
        assertFalse(tokenProvider.validateToken("invalid-token"));
    }

    @Test
    void shouldRejectEmptyToken() {
        assertFalse(tokenProvider.validateToken(""));
    }

    @Test
    void shouldRejectNullToken() {
        assertFalse(tokenProvider.validateToken(null));
    }

    @Test
    void shouldSetCorrectIssuer() {
        String token = tokenProvider.generateToken("user123", Arrays.asList("USER"), null);

        Claims claims = tokenProvider.getClaims(token);

        assertEquals("test-issuer", claims.getIssuer());
    }

    @Test
    void shouldHandleEmptyRolesList() {
        String token = tokenProvider.generateToken("user123", Arrays.asList(), null);

        List<String> roles = tokenProvider.getRolesFromToken(token);

        assertNotNull(roles);
        assertTrue(roles.isEmpty());
    }
}
