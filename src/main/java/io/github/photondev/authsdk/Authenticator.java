package io.github.photondev.authsdk;

import jakarta.validation.Valid;

import io.github.photondev.authsdk.dto.LoginRequest;
import io.github.photondev.authsdk.dto.RegisterRequest;
import io.github.photondev.authsdk.dto.UserResponse;
import io.github.photondev.authsdk.model.AuthValidationResponse;
import io.github.photondev.authsdk.model.User;
import io.github.photondev.authsdk.service.AuthService;
import io.github.photondev.authsdk.service.RedisTokenBlacklistService;
import io.github.photondev.authsdk.service.UserService;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;

import static java.rmi.server.LogStream.log;

@Slf4j
@RequiredArgsConstructor
public class Authenticator {

    private final AuthService authService;
    private final UserService userService;
    private final RedisTokenBlacklistService redisTokenBlacklistService;

    public String homView() {
        return "Welcome";
    }

    public UserResponse saveUser(RegisterRequest request) throws Exception {
        request.setRole("USER");

        User user = authService.signUp(request);
        UserResponse newUser = userService.sendUser(user, null);
        return newUser;

    }

    public UserResponse Authenticate(@Valid LoginRequest cred) throws Exception {

            String token = authService.login(cred);

            userService.getByUsername(cred.getUsername());
            UserResponse authedUser = userService.sendUser(
                    userService.getByUsername(cred.getUsername()),
                    token);
            return authedUser;

    }

    public AuthValidationResponse validateToken(
            @RequestHeader("Authorization") String authorizationHeader) {

        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);
        AuthValidationResponse response = null;

        if ( authService.validate(token)) {
            // 2. Extraire les données de l'utilisateur du jeton (ou d'une BDD)
            response = new AuthValidationResponse(authService.getUserId(token), authService.getUserRole(token));
        }
        return response;
    }

    public UserResponse saveAdmin(@Valid @RequestBody RegisterRequest request) throws Exception {
        request.setRole("ADMIN");
        User user = authService.signUp(request);
        if (user == null) {
            log("Non d'utilisateur déjà pris, veuillez changer ");
            return null;
        }
        UserResponse newUser = userService.sendUser(user, null);
        return newUser;
    }

    public String logout(@RequestHeader("Authorization") String authorizationHeader) {
        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);
            if (redisTokenBlacklistService.isBlacklisted(token)){
                return "Votre session est déjà suspendue";
            }
            redisTokenBlacklistService.add(token);
            return "Vous avez été déconnecté";

    }

}
