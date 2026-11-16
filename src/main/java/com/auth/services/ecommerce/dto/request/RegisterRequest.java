package com.auth.services.ecommerce.dto.request;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;

public record RegisterRequest(
        @NotBlank(message = "Email must not be blank") @Email(message = "Email format not valid") String email,

        @NotBlank(message = "Password must not be blank") String password) {

}
