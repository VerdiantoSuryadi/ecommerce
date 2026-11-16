package com.auth.services.ecommerce.util;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import com.auth.services.ecommerce.dto.response.ApiResponse;

public class ResponseUtil {

    // * Success Response */
    public static <T> ResponseEntity<ApiResponse<T>> successResponse(String message, T data) {
        return new ResponseEntity<>(new ApiResponse<T>(true, message, data, null), HttpStatus.OK);
    }

    public static <T> ResponseEntity<ApiResponse<T>> errorResponse(String message, HttpStatus status) {
        return new ResponseEntity<>(new ApiResponse<T>(false, message, null, null), status);
    }

    public static <T> ResponseEntity<ApiResponse<T>> errorResponse(String message, T error, HttpStatus status) {
        return new ResponseEntity<>(new ApiResponse<T>(false, message, null, error), status);
    }
}
