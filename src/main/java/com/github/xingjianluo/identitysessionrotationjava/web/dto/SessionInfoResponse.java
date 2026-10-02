package com.github.xingjianluo.identitysessionrotationjava.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import java.time.Instant;

/** 设备会话视图：对外标识、客户端/来源、登录时间、最近活跃时间。 */
public record SessionInfoResponse(
        @JsonProperty("session_id") String sessionId,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_name") String clientName,
        @JsonProperty("user_agent") String userAgent,
        String ip,
        @JsonProperty("login_at") Instant loginAt,
        @JsonProperty("last_active_at") Instant lastActiveAt,
        @JsonProperty("current") boolean current
) {
}
