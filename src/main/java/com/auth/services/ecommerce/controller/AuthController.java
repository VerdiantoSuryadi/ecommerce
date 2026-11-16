package com.auth.services.ecommerce.controller;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.auth.services.ecommerce.dto.request.LoginRequest;
import com.auth.services.ecommerce.dto.request.RefreshTokenRequest;
import com.auth.services.ecommerce.dto.request.RegisterRequest;
import com.auth.services.ecommerce.dto.response.ApiResponse;
import com.auth.services.ecommerce.dto.response.TokenResponse;
import com.auth.services.ecommerce.services.AuthService;
import com.auth.services.ecommerce.util.ResponseUtil;

import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

@RestController
@RequiredArgsConstructor
@RequestMapping("/auth")
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<ApiResponse<TokenResponse>> register(@Valid @RequestBody RegisterRequest request) {
        return ResponseUtil.successResponse("Register success", authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<ApiResponse<TokenResponse>> login(@Valid @RequestBody LoginRequest request) {
        return ResponseUtil.successResponse("Login success", authService.login(request));
    }

    @PostMapping("/refresh")
    public ResponseEntity<ApiResponse<TokenResponse>> refreshToken(@Valid @RequestBody RefreshTokenRequest request) {
        return ResponseUtil.successResponse("Refresh token success", authService.refreshToken(request));
    }

    @PostMapping("/logout")
    public ResponseEntity<ApiResponse<Object>> logout(@Valid @RequestBody RefreshTokenRequest request) {
        authService.logout(request);
        return ResponseUtil.successResponse("Logout success", null);
    }

}
