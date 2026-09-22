package com.github.xingjianluo.identitysessionrotationjava.error;

import com.github.xingjianluo.identitysessionrotationjava.web.dto.ErrorResponse;
import org.slf4j.MDC;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.http.converter.HttpMessageNotReadableException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;

/**
 * 全局异常处理：把 {@link AuthException} 映射为对外稳定的错误 JSON。
 * 错误体结构固定：{@code error / error_description / request_id}。
 */
@RestControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(AuthException.class)
    public ResponseEntity<ErrorResponse> handleAuth(AuthException ex) {
        ErrorCode code = ex.getErrorCode();
        ErrorResponse body = new ErrorResponse(code.code(), ex.getMessage(), currentRequestId());
        return ResponseEntity.status(code.httpStatus()).body(body);
    }

    @ExceptionHandler(HttpMessageNotReadableException.class)
    public ResponseEntity<ErrorResponse> handleUnreadable(HttpMessageNotReadableException ex) {
        ErrorResponse body = new ErrorResponse(ErrorCode.BAD_REQUEST.code(),
                "请求体缺失或不是合法 JSON", currentRequestId());
        return ResponseEntity.status(HttpStatus.BAD_REQUEST).body(body);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex) {
        // 兜底：不向客户端泄露内部细节
        ErrorResponse body = new ErrorResponse("internal_error",
                "服务器内部错误", currentRequestId());
        return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body(body);
    }

    private String currentRequestId() {
        String requestId = MDC.get("requestId");
        return requestId != null ? requestId : "-";
    }
}
