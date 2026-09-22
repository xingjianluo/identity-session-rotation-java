package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/** 可查询的审计记录。 */
public record AuditEvent(
        long id,
        Instant at,
        String type,
        String username,
        String familyId,
        String detail
) {
}
