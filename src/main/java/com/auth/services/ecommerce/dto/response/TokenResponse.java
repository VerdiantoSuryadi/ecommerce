package com.auth.services.ecommerce.dto.response;

public record TokenResponse(
                String tokenType,
                String accessToken,
                String refreshToken,
                Long accessExpireIn) {

}
