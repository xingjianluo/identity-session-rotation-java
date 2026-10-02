package com.github.xingjianluo.identitysessionrotationjava.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/** 设备登录视图：familyId 作为该登录对外的稳定标识。 */
public record DeviceSessionResponse(
        @JsonProperty("session_id") String familyId,
        @JsonProperty("client") String client,
        @JsonProperty("created_at") Instant createdAt,
        @JsonProperty("last_active_at") Instant lastActiveAt,
        @JsonProperty("current") boolean current
) {
}
