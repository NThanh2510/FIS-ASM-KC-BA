package com.asm_keycloak.reponsitory;

import com.asm_keycloak.entity.User;
import feign.Param;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;
import java.util.UUID;

public interface UserRepository extends JpaRepository<User, UUID> {
    Optional<User> findByKcUserId(String kcUserId);
    Optional<User> findByUsername(String username);


}
