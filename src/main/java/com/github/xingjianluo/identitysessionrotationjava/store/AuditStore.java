package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEvent;
import java.time.Instant;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import org.springframework.stereotype.Component;

/**
 * 内存审计记录存储：登录失败、刷新失败、撤销与授权拒绝等事件均写入此处，
 * 并可按类型 / 用户名查询。记录只追加，不修改、不删除。
 */
@Component
public class AuditStore {

    private final AtomicLong idSequence = new AtomicLong(0);
    private final CopyOnWriteArrayList<AuditEvent> events = new CopyOnWriteArrayList<>();

    public AuditEvent record(String type, String username, String familyId, String detail) {
        AuditEvent event = new AuditEvent(
                idSequence.incrementAndGet(),
                Instant.now(),
                type,
                username,
                familyId,
                detail);
        events.add(event);
        return event;
    }

    public List<AuditEvent> findAll() {
        return List.copyOf(events);
    }

    public List<AuditEvent> findByType(String type) {
        return events.stream().filter(e -> e.type().equals(type)).toList();
    }

    public List<AuditEvent> findByUsername(String username) {
        return events.stream()
                .filter(e -> username.equals(e.username()))
                .toList();
    }
}
