package io.github.photondev.authsdk.annotation.annotations;

import io.github.photondev.authsdk.annotation.classes.FieldsValueMatchValidator;
import jakarta.validation.Constraint;
import jakarta.validation.Payload;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

@Target({ ElementType.TYPE }) // S'applique à la classe, pas au champ
@Retention(RetentionPolicy.RUNTIME)
@Constraint(validatedBy = FieldsValueMatchValidator.class)
public @interface FieldsValueMatch {
    String message() default "Les champs ne correspondent pas";
    Class<?>[] groups() default {};
    Class<? extends Payload>[] payload() default {};

    String field();        // Nom du premier champ (ex: "password")
    String fieldMatch();   // Nom du second champ (ex: "confirmPassword")

    @Target({ ElementType.TYPE })
    @Retention(RetentionPolicy.RUNTIME)
    @interface List {
        FieldsValueMatch[] value();
    }
}