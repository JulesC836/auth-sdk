package io.github.photondev.authsdk;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.RestController;

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

@Slf4j
@RestController
@RequiredArgsConstructor
public class Authenticator {

    private final AuthService authService;
    private final UserService userService;
    private final RedisTokenBlacklistService redisTokenBlacklistService;

    public String homView() {
        return "Welcome";
    }

    public ResponseEntity<?> saveUser(@Valid @RequestBody RegisterRequest request) throws Exception {
        request.setRole("USER");
        try {
            User user = authService.signUp(request);
            UserResponse newUser = userService.sendUser(user, null);
            return ResponseEntity.ok(newUser);
        } catch (Exception e) {
            return new ResponseEntity<>("Nom d'utilisateur déjà pris, faut changer " + e.getMessage(), HttpStatus.CONFLICT);
        }

    }

    public ResponseEntity<?> Authenticate(@Valid @RequestBody LoginRequest cred) throws Exception {
        try {

            String token = authService.login(cred);

            userService.getByUsername(cred.getUsername());
            UserResponse authedUser = userService.sendUser(
                    userService.getByUsername(cred.getUsername()),
                    token);
            return ResponseEntity.ok(authedUser);
        } catch (BadCredentialsException e) {
            return new ResponseEntity<>("Mauvaises informations d'identification pour: "+ cred.getUsername(), HttpStatus.NOT_FOUND);
        } catch (Exception e) {
            return new ResponseEntity<>("Erreur d'authentification: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }
    }

    public ResponseEntity<AuthValidationResponse> validateToken(
            @RequestHeader("Authorization") String authorizationHeader) {

        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);

        if ( authService.validate(token)) {
            // 2. Extraire les données de l'utilisateur du jeton (ou d'une BDD)

            AuthValidationResponse response = new AuthValidationResponse(authService.getUserId(token), authService.getUserRole(token));
            return ResponseEntity.ok(response);
        } else {
            // Jeton invalide
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).build();
        }
    }

    public ResponseEntity<?> saveAdmin(@Valid @RequestBody RegisterRequest request) throws Exception {
        request.setRole("ADMIN");
        User user = authService.signUp(request);
        if (user == null) {
            return new ResponseEntity<>("Non d'utilisateur déjà pris, veuillez changer ", HttpStatus.CONFLICT);
        }
        UserResponse newUser = userService.sendUser(user, null);
        return ResponseEntity.ok(newUser);

    }

    public ResponseEntity<?> logout(@RequestHeader("Authorization") String authorizationHeader) {
        // 1. Extraire et valider le jeton (Signature, Expiration, etc.)
        String token = authorizationHeader.substring(7);
        try{
            if (redisTokenBlacklistService.isBlacklisted(token)){
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Votre session est déjà suspendue");
            }
            redisTokenBlacklistService.add(token);
            return ResponseEntity.ok("Vous avez été déconnecté");
        }catch(Exception e){
            return new ResponseEntity<>("Erreur lors de la déconnexion: " + e.getMessage(), HttpStatus.BAD_REQUEST);
        }

    }

}
