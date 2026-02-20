package com.example.auth_test.controller;

import com.example.auth_test.dto.UserDTO;
import com.example.auth_test.model.User;
import com.example.auth_test.service.UserService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/api/auth")
public class AuthController {

    private final UserService userService;

    @PostMapping("/register")
    public ResponseEntity<User> register(@RequestBody UserDTO request) {
        User user =  userService.registerUser(request.username(), request.password());
        return ResponseEntity.status(HttpStatus.CREATED).body(user);
    }

    @PostMapping("/login")
    public ResponseEntity<String> login(@RequestBody UserDTO request) {
        String token = userService.loginUser(request.username(), request.password());
        return ResponseEntity.ok(token);
    }

    @GetMapping("/me")
    public ResponseEntity<String> getCurrentUser() {
        return ResponseEntity.ok("Vous êtes authentifié");
    }
    @PostMapping("/logout")
    public ResponseEntity<Void> logout() {
        // Invalidate the token (not implemented in this example)
        return ResponseEntity.ok().build();
    }

}
