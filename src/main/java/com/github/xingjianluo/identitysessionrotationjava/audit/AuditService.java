package com.github.xingjianluo.identitysessionrotationjava.audit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Append-only, queryable audit log. Backed by a copy-on-write list which is
 * safe for concurrent appends and yields stable snapshot queries.
 */
@Service
public class AuditService {

    private static final Logger log = LoggerFactory.getLogger(AuditService.class);

    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    /**
     * Appends one event. Any of {@code accountId} / {@code sessionId} may be
     * null when attribution is impossible (e.g. unknown login username).
     */
    public void record(AuditEventType type, String accountId, String sessionId, String detail) {
        AuditEvent event = new AuditEvent(
                UUID.randomUUID().toString(), Instant.now(), type, accountId, sessionId, detail);
        events.add(event);
        log.info("AUDIT event={} accountId={} sessionId={} detail={}",
                type, accountId, sessionId, detail);
    }

    /**
     * Queries events. Either filter may be null, meaning "do not filter on
     * this field"; results are returned in insertion order.
     */
    public List<AuditEvent> query(AuditEventType type, String accountId) {
        return events.stream()
                .filter(e -> type == null || e.type() == type)
                .filter(e -> accountId == null || accountId.equals(e.accountId()))
                .toList();
    }

    public List<AuditEvent> all() {
        return List.copyOf(events);
    }
}
