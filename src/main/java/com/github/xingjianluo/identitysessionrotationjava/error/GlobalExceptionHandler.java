package com.github.xingjianluo.identitysessionrotationjava.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

import java.time.Instant;
import java.util.Map;

/**
 * Maps {@link ApiException} to the stable error payload
 * {@code {"error": "<ErrorCode>", "message": "...", "timestamp": "..."}}.
 * Unknown failures collapse to a generic INTERNAL_ERROR so no internal
 * detail ever leaks.
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(ApiException.class)
    public ResponseEntity<Map<String, Object>> handleApi(ApiException ex) {
        return ResponseEntity.status(ex.code().httpStatus()).body(Map.of(
                "error", ex.code().name(),
                "message", ex.detail(),
                "timestamp", Instant.now().toString()));
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<Map<String, Object>> handleOther(Exception ex) {
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(Map.of(
                "error", "INTERNAL_ERROR",
                "message", "internal error",
                "timestamp", Instant.now().toString()));
    }
}
