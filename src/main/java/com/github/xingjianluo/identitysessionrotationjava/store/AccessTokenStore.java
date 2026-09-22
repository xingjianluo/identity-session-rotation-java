package com.github.xingjianluo.identitysessionrotationjava.store;

import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import org.springframework.stereotype.Component;

/** 内存访问令牌存储：按令牌哈希索引。 */
@Component
public class AccessTokenStore {

    private final ConcurrentHashMap<String, AccessTokenInfo> byHash = new ConcurrentHashMap<>();
    private final CopyOnWriteArrayList<AccessTokenInfo> all = new CopyOnWriteArrayList<>();

    public void save(AccessTokenInfo info) {
        if (byHash.putIfAbsent(info.getTokenHash(), info) == null) {
            all.add(info);
        }
    }

    public Optional<AccessTokenInfo> findByHash(String hash) {
        return Optional.ofNullable(byHash.get(hash));
    }

    public List<AccessTokenInfo> findByFamily(String familyId) {
        return all.stream().filter(t -> t.getFamilyId().equals(familyId)).toList();
    }
}
