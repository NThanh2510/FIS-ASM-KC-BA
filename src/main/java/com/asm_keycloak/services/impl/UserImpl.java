package com.asm_keycloak.services.impl;

import com.asm_keycloak.dto.identity.Credential;
import com.asm_keycloak.dto.identity.TokenExchangeParam;
import com.asm_keycloak.dto.identity.TokenLoginExchangeParam;
import com.asm_keycloak.dto.identity.UserCreationParam;
import com.asm_keycloak.dto.request.LoginRequest;
import com.asm_keycloak.dto.request.RegistrationRequest;
import com.asm_keycloak.dto.request.UpdateUserRequest;
import com.asm_keycloak.dto.response.LoginResponse;
import com.asm_keycloak.dto.response.UserResponse;
import com.asm_keycloak.entity.User;
import com.asm_keycloak.exception.AppException;
import com.asm_keycloak.exception.ErrorCode;
import com.asm_keycloak.exception.ErrorNormalizer;
import com.asm_keycloak.mapper.UserMapper;
import com.asm_keycloak.reponsitory.IdentityClient;
import com.asm_keycloak.reponsitory.UserRepository;
import com.asm_keycloak.services.UserService;
import com.fasterxml.jackson.databind.ObjectMapper;
import feign.FeignException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.AccessLevel;
import lombok.RequiredArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.adapters.springsecurity.token.KeycloakAuthenticationToken;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;


import java.security.KeyFactory;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.LocalDate;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Service
@Slf4j
@RequiredArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class UserImpl implements UserService {

    UserRepository userRepository;

    UserMapper userMapper;

    IdentityClient identityClient;

    ErrorNormalizer errorNormalizer;

    private ObjectMapper jacksonObjectMapper;

    @Value("${idp.client-secret}")
    @NonFinal
    String clientSecret;

    @Value("${idp.client-id}")
    @NonFinal
    String clientId;


    @Override
    public UserResponse getMyUser() {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String kcUserId = authentication.getName();
        log.info("kcUserId: {}", kcUserId);
        var user = userRepository.findByKcUserId(kcUserId).orElseThrow(
                ()-> new AppException(ErrorCode.USER_NOT_EXISTED));

        return userMapper.toUserResponse(user);
    }

    @Override
    public List<UserResponse> getAllProfiles() {
        var users = userRepository.findAll();

        return users.stream().map(userMapper::toUserResponse).collect(Collectors.toList());
    }

    @Override
    public UserResponse register(RegistrationRequest request) {
        try {
            var token = identityClient.exchangeToken(TokenExchangeParam.builder()
                    .grant_type("client_credentials")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .scope("openid")
                    .build());
            log.info("Token: {}", token);

            var creationResponse = identityClient.createUser(
                    "Bearer " + token.getAccessToken(),
                    UserCreationParam.builder()
                            .username(request.getUsername())
                            .firstName(request.getFirstName())
                            .lastName(request.getLastName())
                            .email(request.getEmail())
                            .enabled(true)
                            .emailVerified(false)
                            .credentials(List.of(Credential.builder()
                                    .type("password")
                                    .temporary(false)
                                    .value(request.getPassword())
                                    .build()))
                            .build());
            String KcUserId = extracUserId(creationResponse);
            log.info("User ID: {}", KcUserId);

            var user = userMapper.toUser(request);
            user.setKcUserId(KcUserId);
            user.setDob(LocalDate.now());
            user = userRepository.save(user);
            log.info("User: {}", user);

            return userMapper.toUserResponse(user);
        }catch (FeignException exception){
            throw errorNormalizer.handleKeyCloakException(exception);
        }
    }

    private String extracUserId(ResponseEntity<?> response) {
        String location = response.getHeaders().get("Location").getFirst();
        String[] split = location.split("/");

        return split[split.length - 1];
    }




    @Override
    public LoginResponse login(LoginRequest request) {
        try {
            // Gửi yêu cầu login và lấy token từ Keycloak
            var token = identityClient.exchangeTokenLogin(TokenLoginExchangeParam.builder()
                    .grant_type("password")
                    .client_id(clientId)
                    .client_secret(clientSecret)
                    .username(request.getUsername())
                    .password(request.getPassword())
                    .scope("openid")
                    .build()); 
            log.info("Token response: {}", token.getAccessToken());
            // Gọi API bảo vệ với token
//            String apiResponse = callProtectedApi(token.getAccessToken());
//            log.info("Protected API response: {}", apiResponse);

            // Lấy vai trò người dùng sau khi đăng nhập
//            List<String> userRoles = getUserRoles();
//            log.info("User roles: {}", userRoles);

            // Trả về thông tin đăng nhập với token
            return LoginResponse.builder()
                    .accessToken(token.getAccessToken())
                    .build();
        } catch (FeignException exception) {
            String errorMessage = exception.contentUTF8();
            log.error("Feign Exception occurred: {}", errorMessage);

            // Xử lý lỗi 401 Unauthorized
            if (exception.status() == 401) {
                log.error("Authentication failed: Invalid credentials or token.");
                return LoginResponse.builder().build();
            }
            // Xử lý các lỗi khác
            throw errorNormalizer.handleKeyCloakException(exception);
        } catch (Exception ex) {
            log.error("Unexpected error occurred during login: {}", ex.getMessage(), ex);
            throw new RuntimeException("An unexpected error occurred during login.", ex);
        }
    }

    @Override
    public void Logout(String id) {
        var authentication = SecurityContextHolder.getContext().getAuthentication();
        String kcUserId = authentication.getName();
        identityClient.logOut(kcUserId);

    }

    public String callProtectedApi(String accessToken) {
        // Địa chỉ API bảo vệ
        String apiUrl = "http://localhost:8180/protected-api";

        // Tạo đối tượng RestTemplate để gửi yêu cầu HTTP
        RestTemplate restTemplate = new RestTemplate();

        // Tạo đối tượng HttpHeaders và thêm token vào trong header Authorization
        HttpHeaders headers = new HttpHeaders();
        headers.setBearerAuth(accessToken);  // Thêm Bearer token vào header

        // Tạo đối tượng HttpEntity chứa headers
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);

        // Gửi yêu cầu GET đến API bảo vệ và nhận phản hồi
        ResponseEntity<String> response = restTemplate.exchange(apiUrl, HttpMethod.GET, requestEntity, String.class);
        return null;
    }

    private List<String> getUserRoles() {
        KeycloakAuthenticationToken authentication =
                (KeycloakAuthenticationToken) SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            log.error("Authentication is null. User might not be logged in.");
            return Collections.emptyList(); // Trả về danh sách vai trò rỗng nếu không có authentication
        }

        Map<String, Object> details = (Map<String, Object>) authentication.getDetails();
        Map<String, Object> realmAccess = (Map<String, Object>) details.get("realm_access");

        if (realmAccess == null) {
            log.error("realm_access is null. User roles cannot be fetched.");
            return Collections.emptyList();
        }

        log.info("realmAccess: {}", realmAccess);
        return (List<String>) realmAccess.get("roles");
    }


    @Override
    public void UpdateUser( UpdateUserRequest request) {
        try {
            var authentication = SecurityContextHolder.getContext().getAuthentication();
            String kcUserId = authentication.getName();
            log.info("KcUserId: {}", kcUserId);
            User user = userRepository.findByKcUserId(kcUserId).orElseThrow();


            user.setFirstName(request.getFirstName());
            user.setLastName(request.getLastName());
            user.setEmail(request.getEmail());

            userRepository.save(user);

        } catch (FeignException exception) {
            throw errorNormalizer.handleKeyCloakException(exception);
        }
    }

    @Override
    public void addRoleToUser(String username, String role) {

    }

    @Override
    public void isAdmin() {

    }


}
