package com.github.xingjianluo.identitysessionrotationjava.audit;

import java.time.Instant;

/**
 * One immutable audit record. {@code accountId} may be null when the event
 * cannot be attributed to a known account (e.g. login for unknown user).
 */
public record AuditEvent(
        String id,
        Instant occurredAt,
        AuditEventType type,
        String accountId,
        String sessionId,
        String detail) {
}
