package com.auth.services.ecommerce.exception;

public class PasswordNotMatchesException extends RuntimeException {

    public PasswordNotMatchesException(String message) {
        super(message);
    }

}
