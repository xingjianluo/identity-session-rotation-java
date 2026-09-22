package com.github.xingjianluo.identitysessionrotationjava.error;

/**
 * Exception carrying a stable {@link ErrorCode}; the single way business
 * logic signals a rejectable decision to the web layer.
 */
public class ApiException extends RuntimeException {

    private final ErrorCode code;
    private final String detail;

    public ApiException(ErrorCode code, String detail) {
        super(detail);
        this.code = code;
        this.detail = detail;
    }

    public ErrorCode code() {
        return code;
    }

    public String detail() {
        return detail;
    }
}
