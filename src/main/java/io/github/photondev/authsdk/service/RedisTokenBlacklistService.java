package io.github.photondev.authsdk.service;

import java.time.Duration;

import io.github.photondev.authsdk.config.utils.JwtUtil;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class RedisTokenBlacklistService {
    private final StringRedisTemplate redisTemplate;
    private final JwtUtil jwtUtil;
    
    private static final String BLACKLIST_KEY_PREFIX = "blacklist:jwt:";
    
    public void add(String token) {
        Duration expiration = Duration.between(java.time.Instant.now(), jwtUtil.extractExpiration(token).toInstant());
        redisTemplate.opsForValue().set(BLACKLIST_KEY_PREFIX + token, "blacklisted", expiration);
    }

    public boolean isBlacklisted(String token) {

        return redisTemplate.hasKey(BLACKLIST_KEY_PREFIX + token);
    }
    
}
