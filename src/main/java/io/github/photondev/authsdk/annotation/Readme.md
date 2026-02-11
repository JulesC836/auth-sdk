
### Utilisation de l'annotation @FieldValueMatch
```Markdown

@FieldsValueMatch(
    field = "password", 
    fieldMatch = "confirmPassword", 
    message = "Le mot de passe de confirmation doit être identique au mot de passe."
)
public class UserRegistrationDto {

    @NotBlank
    @Size(min = 8)
    private String password;

    private String confirmPassword;

    // Getters et Setters...
}
```