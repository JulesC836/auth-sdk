package io.github.photondev.authsdk.service;

import io.github.photondev.authsdk.config.JwtUtil;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import io.github.photondev.authsdk.dto.LoginRequest;
import io.github.photondev.authsdk.dto.RegisterRequest;
import io.github.photondev.authsdk.model.User;
import io.github.photondev.authsdk.repository.UserRepo;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@RequiredArgsConstructor
@Slf4j
@Service
public class AuthService {
    private final UserRepo userRepo;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;
    private final RedisTokenBlacklistService tokenBlacklistService;
    private final JwtUtil jwtUtil;

    public User signUp(RegisterRequest request) throws Exception {
        // Vérifier si l'utilisateur existe déjà
        if (userRepo.findByUsername(request.getUsername()).isPresent()) {
            throw new Exception("L'utilisateur existe déjà");
        }

        User user = User.builder()
                .name(request.getName())
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(request.getRole())
                .build();

        return userRepo.save(user);

    }

    public String login(LoginRequest request) throws Exception {

        log.debug("Tentative de connexion pour: {}", request.getUsername());
        Authentication authenticationInfo = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getUsername(),
                        request.getPassword()));

        log.debug("Authentification réussie pour: {}", request.getUsername());
        String token = jwtService.generateToken(authenticationInfo);
        log.debug("Token généré pour: {}", request.getUsername());

        return token;

    }

    public boolean validate(String token){
        return (jwtService.isTokenValid(token, null) && !tokenBlacklistService.isBlacklisted(token));
    }

    public String getUserId(String token){
        return jwtUtil.extractUsername(token);
    }

    public String getUserRole(String token){
        return jwtUtil.extractRoles(token);
    }
}
