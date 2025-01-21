package com.asm_keycloak.mapper;

import com.asm_keycloak.dto.request.RegistrationRequest;
import com.asm_keycloak.dto.response.UserResponse;
import com.asm_keycloak.entity.User;
import org.mapstruct.Mapper;

@Mapper(componentModel = "spring")
public interface UserMapper {
    User toUser(RegistrationRequest request);

    UserResponse toUserResponse(User user);
}
