package com.asm_keycloak.services;

import com.asm_keycloak.dto.request.LoginRequest;
import com.asm_keycloak.dto.request.RegistrationRequest;
import com.asm_keycloak.dto.request.UpdateUserRequest;
import com.asm_keycloak.dto.response.LoginResponse;
import com.asm_keycloak.dto.response.UserResponse;
import org.springframework.security.access.prepost.PreAuthorize;


import java.util.List;

public interface UserService {
    public UserResponse getMyUser();

    public List<UserResponse> getAllProfiles();

    public UserResponse register(RegistrationRequest request);

    public LoginResponse login (LoginRequest response);

    public void Logout(String id);

    public void  UpdateUser(UpdateUserRequest request);

    public void  addRoleToUser(String username, String role);

    @PreAuthorize("hasRole('ADMIN')")
    public void isAdmin();

}
