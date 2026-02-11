package io.github.photondev.authsdk.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class AuthValidationResponse {
    private String userId;
    private String roles;
}