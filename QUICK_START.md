# Auth SDK - Quick Reference

## 🎯 In 30 Seconds

**Installation:**
```bash
mvn clean install
```

**Use in another project:**
```xml
<dependency>
    <groupId>io.github.photondev</groupId>
    <artifactId>auth-sdk</artifactId>
    <version>1.0.0</version>
</dependency>
```

**Configuration:**
```yaml
jwt:
  auth:
    secret: your-256-bit-minimum-secret-key
    expiration: 86400000  # 24 hours
```

**Generate a token:**
```java
String token = tokenProvider.generateToken(
    "username",
    Arrays.asList("ADMIN", "USER"),
    Map.of("userId", 123)
);
```

**Validate a token:**
```java
if (tokenProvider.validateToken(token)) {
    String username = tokenProvider.getUsernameFromToken(token);
    List<String> roles = tokenProvider.getRolesFromToken(token);
}
```

---

## 📚 Documentation

- **README.md** - Complete API reference and features
- **GUIDE_INTEGRATION.md** - Step-by-step integration guide
- **CORRECTIONS.md** - Details of recent fixes and improvements

---

## 🔧 Configuration Properties

```yaml
jwt:
  auth:
    enabled: true                           # Enable/disable auth
    secret: your-secret-key-min-32-bytes    # REQUIRED
    expiration: 86400000                    # Token validity (ms)
    header: Authorization                   # Header name
    prefix: "Bearer "                       # Token prefix
    issuer: my-app                          # JWT issuer
    blacklist-enabled: true                 # Enable revocation
```

---

## 🧪 Running Tests

```bash
# All tests
mvn clean test

# Specific test class
mvn test -Dtest=JwtTokenProviderTest

# With coverage
mvn clean test jacoco:report
```

---

## 🔒 Security Checklist

- [ ] Secret key is at least 256 bits (32 bytes)
- [ ] Secret key stored in environment variable (not hardcoded)
- [ ] TokenBlacklistService implemented for production (Redis/DB)
- [ ] HTTPS enabled in production
- [ ] Token expiration time configured appropriately
- [ ] Tokens validated before use

---

## ⚡ Common Operations

### Generate Token with Custom Claims
```java
Map<String, Object> claims = Map.of(
    "userId", user.getId(),
    "email", user.getEmail(),
    "department", user.getDepartment()
);

String token = tokenProvider.generateToken(
    user.getUsername(),
    user.getRoles(),
    claims
);
```

### Extract Custom Claim
```java
Long userId = tokenProvider.getClaimFromToken(token, "userId", Long.class);
String email = tokenProvider.getClaimFromToken(token, "email", String.class);
```

### Revoke Token (Logout)
```java
tokenBlacklistService.blacklist(token);
```

### Get Token Expiration
```java
Date expiresAt = tokenProvider.getExpirationDateFromToken(token);
```

---

## 🐛 Troubleshooting

| Problem | Solution |
|---------|----------|
| "Secret must be at least 256 bits" | Use a longer secret (32+ bytes) in application.yml |
| Filter not intercepting requests | Check Spring Security config - ensure filters are added |
| Token blacklist not working | Implement TokenBlacklistService with Redis/DB for production |
| "Authentication failed" response | Check token format ("Bearer " prefix) and validity |

---

## 📞 Support

- Issues: GitHub Issues
- Questions: GitHub Discussions
- Contributing: See README.md

