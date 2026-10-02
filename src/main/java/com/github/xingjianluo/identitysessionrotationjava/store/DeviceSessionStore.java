package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import java.util.Comparator;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 设备登录（多设备会话）存储：按 familyId 索引，可按用户名列出活跃登录。
 */
@Component
public class DeviceSessionStore {

    private final ConcurrentHashMap<String, DeviceSession> byFamilyId =
            new ConcurrentHashMap<>();

    public void save(DeviceSession session) {
        byFamilyId.putIfAbsent(session.getFamilyId(), session);
    }

    public Optional<DeviceSession> findByFamilyId(String familyId) {
        return Optional.ofNullable(byFamilyId.get(familyId));
    }

    public List<DeviceSession> findByUsername(String username) {
        return byFamilyId.values().stream()
                .filter(s -> s.getUsername().equals(username))
                .toList();
    }

    /**
     * 某账号当前活跃登录，按“最久未活动”升序（淘汰顺序即取列表头部）。
     * 并列时按登录时间、再按 familyId 排序，保证结果可预期。
     */
    public List<DeviceSession> findActiveByUsername(String username) {
        return byFamilyId.values().stream()
                .filter(s -> s.getUsername().equals(username))
                .filter(DeviceSession::isActive)
                .sorted(Comparator.comparing(DeviceSession::getLastActiveAt)
                        .thenComparing(DeviceSession::getCreatedAt)
                        .thenComparing(DeviceSession::getFamilyId))
                .toList();
    }
}
