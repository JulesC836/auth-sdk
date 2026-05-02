# Auth SDK - Spring Boot JWT Authentication Starter

A production-ready Spring Boot starter library for JWT (JSON Web Token) authentication. This SDK provides secure token generation, validation, and revocation (blacklist) management, while delegating user management and business logic to your application.

## ✨ Features

✅ **JWT Token Generation & Validation** - Built on JJWT library with HS512 (HMAC-SHA512) signing  
✅ **Spring Security Integration** - Automatic filter configuration for request authentication  
✅ **Token Blacklist Support** - Interface-based design for easy integration with Redis, databases, etc.  
✅ **Spring Boot Auto-Configuration** - Zero-config startup with sensible defaults  
✅ **Fully Customizable** - Extensive configuration properties for all JWT aspects  
✅ **Production-Ready** - Validated secret keys, proper error handling, comprehensive logging  

## 📋 Requirements

- Java 17+
- Spring Boot 3.5.7+
- Spring Security (automatically included via starter)
- Maven 3.6+ or Gradle 7.0+

## 🚀 Quick Start

### 1. Add Dependency

#### Maven
```xml
<dependency>
    <groupId>io.github.photondev</groupId>
    <artifactId>auth-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

#### Gradle
```gradle
implementation 'io.github.photondev:auth-sdk:1.0.0'
```

### 2. Configure JWT in `application.yml`

```yaml
jwt:
  auth:
    enabled: true
    secret: your-super-secret-key-change-in-production-min-256-bits
    expiration: 86400000        # 24 hours in milliseconds
    issuer: my-application
    blacklist-enabled: true
```

**⚠️ CRITICAL**: Use a strong secret key (minimum 256 bits/32 bytes). The SDK will fail to start if the secret is too weak.

### 3. Implement Token Blacklist Service (Optional)

The SDK provides an in-memory implementation for development. For production, implement with Redis or a database:

```java
@Service
public class RedisTokenBlacklistService implements TokenBlacklistService {
    
    private final RedisTemplate<String, String> redisTemplate;
    private static final String PREFIX = "jwt:blacklist:";
    
    @Override
    public void blacklist(String token) {
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
        // No action needed - Redis TTL handles automatic cleanup
    }
}
```

Spring Boot will automatically use your implementation instead of the in-memory default.

### 4. Use in Your Authentication Service

```java
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public AuthResponse login(LoginRequest request) {
        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
            
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }
        
        String token = tokenProvider.generateToken(
            user.getUsername(),
            user.getRoles(),
            Map.of("userId", user.getId(), "email", user.getEmail())
        );
        
        return new AuthResponse(token, user.getUsername());
    }
    
    public void logout(String token) {
        tokenProvider.validateToken(token); // Verify it's valid before revoking
        // TokenBlacklistFilter will handle revocation automatically
    }
}
```

### 5. Create REST Endpoints

```java
@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {
    
    private final AuthService authService;
    private final TokenBlacklistService blacklistService;
    private final JwtTokenProvider tokenProvider;
    
    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(@RequestBody @Valid LoginRequest request) {
        return ResponseEntity.ok(authService.login(request));
    }
    
    @PostMapping("/logout")
    public ResponseEntity<String> logout(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7); // Remove "Bearer "
        blacklistService.blacklist(token);
        return ResponseEntity.ok("Logged out successfully");
    }
    
    @GetMapping("/validate")
    public ResponseEntity<Map<String, Object>> validate(@RequestHeader("Authorization") String authHeader) {
        String token = authHeader.substring(7);
        
        if (tokenProvider.validateToken(token) && !blacklistService.isBlacklisted(token)) {
            return ResponseEntity.ok(Map.of(
                "valid", true,
                "username", tokenProvider.getUsernameFromToken(token),
                "roles", tokenProvider.getRolesFromToken(token)
            ));
        }
        
        return ResponseEntity.ok(Map.of("valid", false));
    }
}
```

## ⚙️ Configuration Properties

All properties are under the `jwt.auth` prefix:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable JWT authentication module |
| `secret` | string | **required** | Secret key for signing tokens (min 256 bits) |
| `expiration` | long | `86400000` | Token validity in milliseconds (24h default) |
| `header` | string | `Authorization` | HTTP header name containing the token |
| `prefix` | string | `Bearer ` | Token prefix in the header (e.g., "Bearer ", "Token ") |
| `issuer` | string | `auth-sdk` | JWT issuer claim value |
| `blacklist-enabled` | boolean | `true` | Enable/disable token revocation support |

### Environment Variables Example

```yaml
jwt:
  auth:
    enabled: true
    secret: ${JWT_SECRET}           # Required - set via environment variable
    expiration: ${JWT_EXPIRATION:3600000}  # 1 hour default
    issuer: ${APP_NAME:my-app}
    blacklist-enabled: true
```

## 🔧 Advanced Usage

### Custom JWT Claims

Add application-specific data to tokens:

```java
Map<String, Object> customClaims = Map.of(
    "userId", user.getId(),
    "email", user.getEmail(),
    "department", user.getDepartment(),
    "permissions", user.getPermissions()
);

String token = tokenProvider.generateToken(
    user.getUsername(),
    user.getRoles(),
    customClaims
);
```

### Extract Custom Claims

```java
Long userId = tokenProvider.getClaimFromToken(token, "userId", Long.class);
String email = tokenProvider.getClaimFromToken(token, "email", String.class);
List<String> roles = tokenProvider.getRolesFromToken(token);
```

### Generate Token from Spring Authentication

```java
@PostMapping("/spring-login")
public ResponseEntity<String> springLogin(Authentication authentication) {
    String token = tokenProvider.generateToken(authentication);
    return ResponseEntity.ok(token);
}
```

### Disable Token Blacklist (if not needed)

```yaml
jwt:
  auth:
    blacklist-enabled: false
```

## 🏗️ Architecture

The SDK is intentionally minimal and focuses on JWT infrastructure only. It does **NOT** include:

- ❌ User entities or repositories
- ❌ Login/register request DTOs
- ❌ REST endpoints or controllers
- ❌ Password encoding (use Spring Security's `PasswordEncoder`)
- ❌ Database dependencies
- ❌ Refresh token logic

These responsibilities remain with your application. See the `example/` directory for a reference implementation.

## 🔒 Security Best Practices

1. **Secret Key Management**
   - Use a strong secret (minimum 256 bits)
   - Store in environment variables, never hardcode
   - Use a secrets manager (Vault, AWS Secrets Manager, etc.) in production

2. **HTTPS Only**
   - Always use HTTPS in production
   - Tokens sent in plain HTTP can be intercepted

3. **Token Expiration**
   - Set appropriate expiration times (default: 24 hours)
   - Shorter expiration for sensitive operations
   - Implement refresh tokens for long-lived sessions

4. **Blacklist Strategy**
   - Use distributed storage (Redis, database) for production
   - **NOT** suitable for in-memory blacklist in multi-instance deployments
   - Clean up expired tokens periodically

5. **Token Validation**
   - Always validate tokens before granting access
   - Check blacklist status for revoked tokens
   - Validate claims match expected values

## ❌ Common Mistakes

### Secret Key Too Short
```
Error: JWT secret must be at least 256 bits (32 bytes)
```
**Fix**: Use a longer secret key in `application.yml`

### Using InMemory Blacklist in Production
**Problem**: Tokens blacklisted on one server instance won't be blacklisted on others
**Fix**: Implement `TokenBlacklistService` with Redis or database

### Not Validating Token Before Use
**Problem**: Accepting invalid or expired tokens
**Fix**: Always call `tokenProvider.validateToken(token)` before extracting claims

### Storing Tokens in Local Storage (Frontend)
**Problem**: Vulnerable to XSS attacks
**Better**: Use httpOnly, secure cookies instead

## 📚 API Reference

### JwtTokenProvider

```java
// Generate token with roles and custom claims
String generateToken(String username, Collection<String> roles, Map<String, Object> additionalClaims);

// Generate from Spring Authentication
String generateToken(Authentication authentication);

// Validate token signature and expiration
boolean validateToken(String token);

// Extract information
String getUsernameFromToken(String token);
List<String> getRolesFromToken(String token);
<T> T getClaimFromToken(String token, String claimName, Class<T> type);
Claims getClaims(String token);
Date getExpirationDateFromToken(String token);
```

### TokenBlacklistService (Interface)

```java
void blacklist(String token);           // Add token to blacklist
boolean isBlacklisted(String token);    // Check if blacklisted
void remove(String token);              // Remove from blacklist
void cleanupExpired();                  // Clean expired tokens
```

## 🧪 Testing

The SDK includes unit tests for core components:

```bash
mvn clean test
```

Example test cases cover:
- Token generation with various claim types
- Token validation (valid, expired, invalid signature)
- Custom claim extraction
- Secret key validation
- Blacklist filter behavior

## 📄 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request with tests

## 📞 Support

- 📖 See `GUIDE_INTEGRATION.md` for step-by-step integration instructions
- 🐛 Report issues on GitHub
- 💬 Ask questions via GitHub Discussions

---

## Version History

### 1.0.0 (Current)
- ✅ JWT token generation and validation with HS512
- ✅ Token blacklist support with pluggable backend
- ✅ Spring Security integration
- ✅ Spring Boot auto-configuration
- ✅ Comprehensive unit tests
- ✅ Production-ready security features
