package com.asm_keycloak.reponsitory;


import com.asm_keycloak.dto.identity.TokenExchangeParam;
import com.asm_keycloak.dto.identity.TokenExchangeResponse;
import com.asm_keycloak.dto.identity.TokenLoginExchangeParam;
import com.asm_keycloak.dto.identity.UserCreationParam;
import com.asm_keycloak.dto.request.UpdateUserRequest;
import feign.QueryMap;
import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@FeignClient(name = "identity-client", url = "${idp.url}")
public interface IdentityClient {
    @PostMapping(value = "/realms/keycloak_demo/protocol/openid-connect/token",
    consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenExchangeResponse exchangeToken(@QueryMap TokenExchangeParam param);

    @PostMapping(value = "/realms/keycloak_demo/protocol/openid-connect/token",
            consumes = MediaType.APPLICATION_FORM_URLENCODED_VALUE)
    TokenExchangeResponse exchangeTokenLogin(@QueryMap TokenLoginExchangeParam param);

    @PostMapping(value = "/admin/realms/keycloak_demo/users",
            consumes = MediaType.APPLICATION_JSON_VALUE)
    ResponseEntity<?> createUser(
            @RequestHeader("authorization") String token,
            @RequestBody UserCreationParam param);

    @PutMapping("/admin/realms/keycloak_demo/users/{id}")
    void updateUser(@RequestHeader("Authorization")String token,
                    @PathVariable("id") String userId,
                    @RequestBody UpdateUserRequest request);
    @PostMapping ("/admin/realms/keycloak_demo/users/{id}/logout")
    void logOut(@PathVariable("id") String Id);
}
