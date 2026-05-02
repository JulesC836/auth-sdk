# Integration Guide - Auth SDK

Step-by-step guide to integrate the Auth SDK into your Spring Boot application.

## Step 1: Install SDK to Local Maven Repository

From the auth-sdk project root directory:

```bash
mvn clean install
```

This will:
- Compile the project
- Run unit tests
- Create `auth-sdk-1.0.0.jar`
- Install it in `~/.m2/repository`

## Step 2: Add Dependency to Your Project

In your project's `pom.xml`:

```xml
<dependency>
    <groupId>io.github.photondev</groupId>
    <artifactId>auth-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

Ensure you also have Spring Security (usually inherited from `spring-boot-starter-security`):

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

## Step 3: Configure JWT Properties

In your `application.yml` or `application.properties`:

### YAML Format

```yaml
jwt:
  auth:
    enabled: true                                    # Enable/disable auth module
    secret: your-256-bit-secret-key-stored-securely # REQUIRED - at least 32 bytes
    expiration: 86400000                             # Token validity (24 hours)
    header: Authorization                            # HTTP header name (default)
    prefix: "Bearer "                                # Token prefix (default)
    issuer: my-application                           # JWT issuer claim
    blacklist-enabled: true                          # Enable token revocation
```

### Properties Format

```properties
jwt.auth.enabled=true
jwt.auth.secret=your-256-bit-secret-key-stored-securely
jwt.auth.expiration=86400000
jwt.auth.header=Authorization
jwt.auth.prefix=Bearer 
jwt.auth.issuer=my-application
jwt.auth.blacklist-enabled=true
```

## Step 4: Environment Variables (Recommended for Production)

Instead of hardcoding secrets, use environment variables:

```yaml
jwt:
  auth:
    secret: ${JWT_SECRET}
    expiration: ${JWT_EXPIRATION:86400000}
    issuer: ${APP_NAME:default-app}
    blacklist-enabled: ${JWT_BLACKLIST_ENABLED:true}
```

Then set environment variables:
```bash
export JWT_SECRET="your-very-long-secret-key-with-at-least-256-bits"
```

## Step 5: Implement Token Blacklist Service (Production)

For development, the SDK provides an in-memory implementation. For production, implement with Redis:

```java
package com.example.service;

import io.github.photondev.authsdk.service.TokenBlacklistService;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import java.util.concurrent.TimeUnit;

@Service
public class RedisTokenBlacklistService implements TokenBlacklistService {
    
    private final RedisTemplate<String, String> redisTemplate;
    private static final String PREFIX = "jwt:blacklist:";
    
    public RedisTokenBlacklistService(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    
    @Override
    public void blacklist(String token) {
        // Store token with 24-hour TTL
        redisTemplate.opsForValue().set(PREFIX + token, "1", 24, TimeUnit.HOURS);
    }
    
    @Override
    public boolean isBlacklisted(String token) {
        return Boolean.TRUE.equals(redisTemplate.hasKey(PREFIX + token));
    }

    @Override
    public void remove(String token) {
        redisTemplate.delete(PREFIX + token);
    }

    @Override
    public void cleanupExpired() {
        // Not needed - Redis handles TTL automatically
    }
}
```

Add Redis dependency to your `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis</artifactId>
</dependency>
```

## Step 6: Create Authentication Service

```java
package com.example.service;

import io.github.photondev.authsdk.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.entity.User;
import com.example.repository.UserRepository;
import java.util.Map;

@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public AuthTokenResponse login(String username, String password) {
        User user = userRepository.findByUsername(username)
            .orElseThrow(() -> new AuthenticationException("User not found"));
        
        if (!passwordEncoder.matches(password, user.getPassword())) {
            throw new AuthenticationException("Invalid password");
        }
        
        String token = tokenProvider.generateToken(
            user.getUsername(),
            user.getRoles(),  // List of role names like ["ADMIN", "USER"]
            Map.of(
                "userId", user.getId(),
                "email", user.getEmail()
            )
        );
        
        return new AuthTokenResponse(token, user.getUsername());
    }
}
```

## Step 7: Create REST Endpoints

```java
package com.example.controller;

import io.github.photondev.authsdk.service.JwtTokenProvider;
import io.github.photondev.authsdk.service.TokenBlacklistService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import com.example.dto.LoginRequest;
import com.example.service.AuthService;
import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final JwtTokenProvider tokenProvider;
    private final TokenBlacklistService blacklistService;
    
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody LoginRequest request) {
        try {
            AuthTokenResponse response = authService.login(
                request.getUsername(), 
                request.getPassword()
            );
            return ResponseEntity.ok(response);
        } catch (AuthenticationException e) {
            return ResponseEntity.status(401).body(Map.of("error", e.getMessage()));
        }
    }
    
    @PostMapping("/logout")
    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.badRequest().body(Map.of("error", "Missing token"));
        }
        
        String token = authHeader.substring(7);
        
        if (!tokenProvider.validateToken(token)) {
            return ResponseEntity.badRequest().body(Map.of("error", "Invalid token"));
        }
        
        blacklistService.blacklist(token);
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
    
    @GetMapping("/validate")
    public ResponseEntity<?> validate(@RequestHeader("Authorization") String authHeader) {
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            return ResponseEntity.ok(Map.of("valid", false));
        }
        
        String token = authHeader.substring(7);
        
        if (!tokenProvider.validateToken(token) || blacklistService.isBlacklisted(token)) {
            return ResponseEntity.ok(Map.of("valid", false));
        }
        
        return ResponseEntity.ok(Map.of(
            "valid", true,
            "username", tokenProvider.getUsernameFromToken(token),
            "roles", tokenProvider.getRolesFromToken(token),
            "expires", tokenProvider.getExpirationDateFromToken(token)
        ));
    }
}
```

## Step 8: Configure Spring Security

Create a `SecurityConfig` class to configure how the authentication filters are applied:

```java
package com.example.config;

import io.github.photondev.authsdk.filter.JwtAuthenticationFilter;
import io.github.photondev.authsdk.filter.TokenBlacklistFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    
    private final TokenBlacklistFilter tokenBlacklistFilter;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;
    
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
    
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .csrf(csrf -> csrf.disable())  // Disable CSRF for stateless JWT auth
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS))  // No sessions
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/api/auth/login", "/api/auth/register").permitAll()
                .requestMatchers("/api/public/**").permitAll()
                .requestMatchers("/health").permitAll()
                .anyRequest().authenticated()
            )
            // Important: TokenBlacklistFilter MUST be before JwtAuthenticationFilter
            .addFilterBefore(tokenBlacklistFilter, UsernamePasswordAuthenticationFilter.class)
            .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        
        return http.build();
    }
}
```

## Step 9: Verify Auto-Configuration

On startup, you should see logs like:

```
🔐 JWT Authentication SDK activé
✅ Configuration JwtTokenProvider
✅ Configuration JwtAuthenticationFilter
✅ Configuration TokenBlacklistFilter
```

## Step 10: Test the Integration

### Login Request
```bash
curl -X POST http://localhost:8080/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"testuser","password":"password123"}'
```

Response:
```json
{
  "token": "eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9...",
  "username": "testuser"
}
```

### Use Token to Access Protected Resource
```bash
curl -X GET http://localhost:8080/api/protected \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
```

### Logout (Revoke Token)
```bash
curl -X POST http://localhost:8080/api/auth/logout \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
```

### Validate Token
```bash
curl -X GET http://localhost:8080/api/auth/validate \
  -H "Authorization: Bearer eyJhbGciOiJIUzUxMiIsInR5cCI6IkpXVCJ9..."
```

## Troubleshooting

### "Secret key is too short" Error
**Problem**: Your JWT secret is less than 256 bits (32 bytes)
**Solution**: Set a stronger secret in `application.yml`

```yaml
jwt:
  auth:
    secret: this-is-a-very-long-secret-key-with-at-least-256-bits-of-entropy-for-hs512
```

### Beans Not Auto-Configured
**Problem**: `JwtTokenProvider` bean not found
**Solution**: Ensure `spring-boot-starter-security` is in dependencies

### "Token révoqué" Error
**Problem**: Your token is blacklisted (you logged out)
**Solution**: Log in again to get a new token

### Filter Order Issues
**Problem**: Tokens not being validated
**Solution**: Ensure filter order in `SecurityConfig`:
1. `TokenBlacklistFilter` (check revocation)
2. `JwtAuthenticationFilter` (extract and validate)

## Production Checklist

- [ ] Use environment variables for `jwt.auth.secret`
- [ ] Implement `TokenBlacklistService` with Redis or database
- [ ] Enable HTTPS (never use HTTP with tokens)
- [ ] Set appropriate token expiration times
- [ ] Implement refresh token logic (if needed)
- [ ] Add request logging and monitoring
- [ ] Monitor failed authentication attempts
- [ ] Regular security audits

## Next Steps

- See `README.md` for detailed API documentation
- Check `exemple/` directory for a complete working example
- Read Spring Security documentation: https://spring.io/projects/spring-security

