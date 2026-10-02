package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/**
 * 内存设备会话存储：按 familyId 索引，并按 username 维护有序列表。
 *
 * <p>列表以“插入顺序”追加（每次新登录追加），因此在 lastActiveAt 相同时
 * 列表顺序即登录先后，可作为超限淘汰的确定性决胜依据。
 */
@Component
public class DeviceSessionStore {

    private final ConcurrentHashMap<String, DeviceSession> byFamily = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<DeviceSession> all = new CopyOnWriteArrayList<>();

    public void save(DeviceSession device) {
        if (byFamily.putIfAbsent(device.getFamilyId(), device) == null) {
            all.add(device);
        }
    }

    public Optional<DeviceSession> findByFamily(String familyId) {
        return Optional.ofNullable(byFamily.get(familyId));
    }

    public List<DeviceSession> findByUsername(String username) {
        if (username == null) {
            return List.of();
        }
        String key = username.toLowerCase();
        return all.stream().filter(d -> d.getUsername().equalsIgnoreCase(key)).toList();
    }

    /** 删除设备记录（撤销后调用）。 */
    public void remove(String familyId) {
        DeviceSession removed = byFamily.remove(familyId);
        if (removed != null) {
            all.remove(removed);
        }
    }
}
