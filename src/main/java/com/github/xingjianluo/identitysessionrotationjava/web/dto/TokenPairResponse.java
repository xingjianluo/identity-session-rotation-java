package com.github.xingjianluo.identitysessionrotationjava.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** 登录/刷新成功响应：短期访问令牌 + 一次性刷新令牌。 */
public record TokenPairResponse(
        @JsonProperty("access_token") String accessToken,
        @JsonProperty("refresh_token") String refreshToken,
        @JsonProperty("token_type") String tokenType,
        @JsonProperty("expires_in") long expiresIn
) {
}
