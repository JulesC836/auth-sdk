package com.example.auth_test.service;

import com.example.auth_test.model.User;
import com.example.auth_test.repo.UserRepository;
import io.github.photondev.authsdk.config.JwtAuthProperties;
import io.github.photondev.authsdk.service.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final JwtAuthProperties jwtAuthProperties;
    private final JwtTokenProvider jwtTokenProvider;


     public User registerUser(String username, String password) {
         User user = new User(username, password);
         userRepository.save(user);
         return user;
    }


     public String loginUser(String username, String password) {
         Optional<User> userOpt = userRepository.findByUsername(username);
            if (userOpt.isEmpty() || !userOpt.get().getPassword().equals(password)) {
                throw new RuntimeException("Invalid username or password");
            }
            User user = userOpt.get();

         return jwtTokenProvider.generateToken(username, Collections.singleton(user.getRole()), null);

    }
}
