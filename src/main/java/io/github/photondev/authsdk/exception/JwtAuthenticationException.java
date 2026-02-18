package io.github.photondev.authsdk.exception;

import org.springframework.security.core.AuthenticationException;

/**
 * Custom exception for JWT authentication errors
 */
public class JwtAuthenticationException extends AuthenticationException {

    public JwtAuthenticationException(String message) {
        super(message);
    }

    public JwtAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }
}
