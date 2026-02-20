# Auth SDK - Spring Boot JWT Authentication Starter

A minimal, production-ready Spring Boot starter for JWT authentication. This SDK provides the infrastructure for JWT token generation, validation, and blacklist management while leaving business logic (user models, DTOs, repositories) to your application.

## Features

✅ **JWT Token Generation & Validation** - Built on JJWT library with HS512 signing  
✅ **Spring Security Integration** - Automatic filter configuration  
✅ **Token Blacklist Support** - Interface-based design, bring your own implementation  
✅ **Auto-Configuration** - Zero-config startup with sensible defaults  
✅ **Customizable** - Extensive configuration properties  
✅ **Production-Ready** - Conditional bean creation, proper error handling  

## Installation

### Maven

```xml
<dependency>
    <groupId>io.github.photondev</groupId>
    <artifactId>auth-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

### Gradle

```gradle
implementation 'io.github.photondev:auth-sdk:1.1.0'
```

## Quick Start

### 1. Add Configuration

Add to your `application.yml`:

```yaml
jwt:
  auth:
    enabled: true
    secret: your-super-secret-key-change-in-production-min-256-bits
    expiration: 86400000  # 24 hours in milliseconds
    issuer: my-application
    blacklist-enabled: true
```

⚠️ **Important**: Use a strong secret key (minimum 256 bits for HS512)

### 2. Implement Token Blacklist Service

The SDK provides an interface - implement it with your storage backend:

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
}
```

> **Note**: An in-memory implementation is provided for development, but should NOT be used in production.

### 3. Use JWT Token Provider

Inject `JwtTokenProvider` in your authentication service:

```java
@Service
@RequiredArgsConstructor
public class AuthService {
    
    private final JwtTokenProvider tokenProvider;
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    
    public AuthResponse login(LoginRequest request) {
        // 1. Authenticate user (your business logic)
        User user = userRepository.findByUsername(request.getUsername())
            .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));
            
        if (!passwordEncoder.matches(request.getPassword(), user.getPassword())) {
            throw new BadCredentialsException("Invalid credentials");
        }
        
        // 2. Generate JWT token
        String token = tokenProvider.generateToken(
            user.getUsername(),
            Collections.singletonList(user.getRole()),
            Map.of("userId", user.getId(), "email", user.getEmail())
        );
        
        // 3. Return response
        return new AuthResponse(token, user.getUsername(), user.getRole());
    }
}
```

### 4. Create Controller Endpoints

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
            String username = tokenProvider.getUsernameFromToken(token);
            List<String> roles = tokenProvider.getRolesFromToken(token);
            
            return ResponseEntity.ok(Map.of(
                "valid", true,
                "username", username,
                "roles", roles
            ));
        }
        
        return ResponseEntity.ok(Map.of("valid", false));
    }
}
```

## Configuration Properties

All properties are under the `jwt.auth` prefix:

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `enabled` | boolean | `true` | Enable/disable JWT authentication |
| `secret` | string | **required** | Secret key for signing tokens (min 256 bits) |
| `expiration` | long | `86400000` | Token validity in milliseconds (24h) |
| `header` | string | `Authorization` | HTTP header containing the token |
| `prefix` | string | `Bearer ` | Token prefix in the header |
| `issuer` | string | `auth-sdk` | JWT issuer claim |
| `blacklist-enabled` | boolean | `true` | Enable/disable token blacklist feature |

### Example Configuration

```yaml
jwt:
  auth:
    enabled: true
    secret: ${JWT_SECRET:default-secret-key-change-me}
    expiration: 3600000  # 1 hour
    header: X-Auth-Token
    prefix: "Token "
    issuer: my-company-app
    blacklist-enabled: true
```

## Advanced Usage

### Custom Claims

Add custom data to tokens:

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
```

### Generate from Spring Security Authentication

```java
@PostMapping("/spring-login")
public ResponseEntity<AuthResponse> springLogin(Authentication authentication) {
    // Auto-extracts username and authorities from Authentication
    String token = tokenProvider.generateToken(authentication);
    return ResponseEntity.ok(new AuthResponse(token));
}
```

### Disable Blacklist

If you don't need logout functionality:

```yaml
jwt:
  auth:
    blacklist-enabled: false
```

## Architecture

This is a **minimal starter** focused on JWT infrastructure. It does NOT include:

- ❌ User entities or repositories
- ❌ DTOs (login/register requests)
- ❌ Controllers or REST endpoints
- ❌ Password encoding
- ❌ Database dependencies

These are **your application's responsibility**. See the `example/` package for reference implementations.

## Security Considerations

1. **Secret Key**: Use a strong secret key (minimum 256 bits). Store in environment variables, never hardcode.
2. **HTTPS Only**: Always use HTTPS in production to prevent token interception.
3. **Token Expiration**: Set appropriate expiration times based on your security requirements.
4. **Blacklist Storage**: Use distributed storage (Redis, database) for production blacklists.
5. **Validation**: Always validate tokens AND check blacklist before granting access.

## Example DTOs

Reference DTOs are provided in the `io.github.photondev.authsdk.example.dto` package:

- `LoginRequest` - Basic login DTO
- `RegisterRequest` - Registration with password confirmation
- `UserResponse` - Authentication response with token

These are examples only - create your own to match your business requirements.

## Troubleshooting

### Beans not auto-configured

Ensure Spring Security is on the classpath:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-security</artifactId>
</dependency>
```

### "Secret key is too short" error

Your secret must be at least 256 bits (32 characters) for HS512:

```yaml
jwt:
  auth:
    secret: this-is-a-very-long-secret-key-with-at-least-256-bits-of-entropy
```

### InMemoryTokenBlacklistService warning

This is expected - replace with your own implementation:

```java
@Bean
@Primary
public TokenBlacklistService tokenBlacklistService() {
    return new RedisTokenBlacklistService(...);
}
```

## License

This project is licensed under the terms specified in the parent project.

## Contributing

Contributions are welcome! Please submit pull requests or open issues.

## Support

For issues, questions, or feature requests, please open an issue on GitHub.
