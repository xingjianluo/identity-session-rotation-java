package com.github.xingjianluo.identitysessionrotationjava.web.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

/** “退出其他所有设备”结果。 */
public record RevokeOthersResponse(
        @JsonProperty("revoked_count") int revokedCount
) {
}
