package io.github.photondev.authsdk.filter;

import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import io.github.photondev.authsdk.util.TokenExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import java.io.IOException;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TokenBlacklistFilterTest {

    @Mock
    private TokenBlacklistService blacklistService;

    @Mock
    private FilterChain filterChain;

    private TokenBlacklistFilter filter;
    private JwtAuthProperties properties;
    private MockHttpServletRequest request;
    private MockHttpServletResponse response;

    @BeforeEach
    void setUp() {
        properties = new JwtAuthProperties();
        properties.setHeader("Authorization");
        properties.setPrefix("Bearer ");

        filter = new TokenBlacklistFilter(blacklistService, properties);
        request = new MockHttpServletRequest();
        response = new MockHttpServletResponse();
    }

    @Test
    void shouldAllowRequestWithoutToken() throws Exception {
        // No Authorization header

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(200, response.getStatus());
        verify(filterChain, times(1)).doFilter(request, response);
        verify(blacklistService, never()).isBlacklisted(anyString());
    }

    @Test
    void shouldAllowRequestWithNonBlacklistedToken() throws Exception {
        String token = "valid-jwt-token";
        request.addHeader("Authorization", "Bearer " + token);
        when(blacklistService.isBlacklisted(token)).thenReturn(false);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(200, response.getStatus());
        verify(filterChain, times(1)).doFilter(request, response);
        verify(blacklistService, times(1)).isBlacklisted(token);
    }

    @Test
    void shouldRejectRequestWithBlacklistedToken() throws Exception {
        String token = "blacklisted-token";
        request.addHeader("Authorization", "Bearer " + token);
        when(blacklistService.isBlacklisted(token)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        assertEquals(401, response.getStatus());
        verify(filterChain, never()).doFilter(request, response);
        verify(blacklistService, times(1)).isBlacklisted(token);

        String content = response.getContentAsString();
        assertTrue(content.contains("Token révoqué"));
    }

    @Test
    void shouldHandleWrongTokenPrefix() throws Exception {
        request.addHeader("Authorization", "Basic abc123");

        filter.doFilterInternal(request, response, filterChain);

        // Token extraction will return null, filter chain should proceed
        assertEquals(200, response.getStatus());
        verify(filterChain, times(1)).doFilter(request, response);
    }

    @Test
    void shouldSetCorrectContentType() throws Exception {
        String token = "blacklisted-token";
        request.addHeader("Authorization", "Bearer " + token);
        when(blacklistService.isBlacklisted(token)).thenReturn(true);

        filter.doFilterInternal(request, response, filterChain);

        assertTrue(response.getContentType().contains("application/json"));
    }
}
