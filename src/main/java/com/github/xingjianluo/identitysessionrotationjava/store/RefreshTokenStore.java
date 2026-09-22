package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/** 内存刷新令牌存储：按令牌哈希索引。 */
@Component
public class RefreshTokenStore {

    private final ConcurrentHashMap<String, RefreshTokenInfo> byHash = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<RefreshTokenInfo> all = new CopyOnWriteArrayList<>();

    public void save(RefreshTokenInfo info) {
        if (byHash.putIfAbsent(info.getTokenHash(), info) == null) {
            all.add(info);
        }
    }

    public Optional<RefreshTokenInfo> findByHash(String hash) {
        return Optional.ofNullable(byHash.get(hash));
    }

    public List<RefreshTokenInfo> findByFamily(String familyId) {
        return all.stream().filter(t -> t.getFamilyId().equals(familyId)).toList();
    }
}
