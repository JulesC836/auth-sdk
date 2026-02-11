package io.github.photondev.authsdk.dto;

import com.fasterxml.jackson.annotation.JsonIgnore;
import jakarta.validation.constraints.AssertTrue;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RegisterRequest {
    @NotBlank(message = "The username is mandatory")
    @Size(min = 4, message = "The username must be at least 4 characters")
    private String username;

    private String name;

    @NotBlank(message = "The password is mandatory")
    @Size(min = 4, message = "The password must be at least 8 characters")
    private String password;

    @NotBlank(message = "The password confirmation is mandatory")
    private String confirm;
    private String role;

    @JsonIgnore
    @AssertTrue(message = "Les mots de passe ne correspondent pas")
    public boolean isPasswordsMatching(){
        return this.password.equals(this.confirm);
    }
}
