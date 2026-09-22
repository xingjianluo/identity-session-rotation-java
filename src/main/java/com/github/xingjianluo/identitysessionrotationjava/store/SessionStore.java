package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.domain.Session;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/**
 * 内存会话存储：按 id / family / username 建索引，并记录 family 级别的撤销原因。
 *
 * <p>family 撤销原因只在“整条会话链被撤销”时写入（登出、改密、停用、重放、过期清理）；
 * 正常刷新轮换只结束旧会话、不写 family 原因。原因取首次值（终态语义）。
 */
@Component
public class SessionStore {

    private final ConcurrentHashMap<String, Session> byId = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<Session> all = new CopyOnWriteArrayList<>();
    private final ConcurrentHashMap<String, RevocationReason> familyReasons =
            new ConcurrentHashMap<>();

    public void save(Session session) {
        if (byId.putIfAbsent(session.getId(), session) == null) {
            all.add(session);
        }
    }

    public Optional<Session> findById(String sessionId) {
        return Optional.ofNullable(byId.get(sessionId));
    }

    public List<Session> findByFamily(String familyId) {
        return all.stream().filter(s -> s.getFamilyId().equals(familyId)).toList();
    }

    public List<Session> findByUsername(String username) {
        return all.stream().filter(s -> s.getUsername().equals(username)).toList();
    }

    /** 记录会话链撤销原因；重复写入不覆盖首次原因。 */
    public void markFamilyRevoked(String familyId, RevocationReason reason) {
        familyReasons.putIfAbsent(familyId, reason);
    }

    public Optional<RevocationReason> findFamilyRevocationReason(String familyId) {
        return Optional.ofNullable(familyReasons.get(familyId));
    }
}
