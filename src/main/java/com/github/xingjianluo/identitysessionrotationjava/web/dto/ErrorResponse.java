package com.github.xingjianluo.identitysessionrotationjava.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** 对外稳定错误响应。 */
public record ErrorResponse(
        @JsonProperty("error") String code,
        @JsonProperty("error_description") String message,
        @JsonProperty("request_id") String requestId
) {
}
