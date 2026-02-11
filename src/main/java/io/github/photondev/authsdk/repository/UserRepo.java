package io.github.photondev.authsdk.repository;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import io.github.photondev.authsdk.model.User;

public interface UserRepo extends JpaRepository<User, Long>{
    Optional<User> findByUsername(String username);
}
