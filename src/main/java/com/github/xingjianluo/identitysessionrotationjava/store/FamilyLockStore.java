package com.github.xingjianluo.identitysessionrotationjava.store;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 按会话链 familyId 提供互斥锁对象。
 *
 * <p>刷新流程在持有该 family 锁的区间内完成「校验旧令牌 → 标记消费 →
 * 签发新令牌」，因此同一刷新令牌的并发请求只有一个能成功，不会产生
 * 两个并行的后继令牌；不同 family 之间完全并行。
 */
@Component
public class FamilyLockStore {

    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    public Object lockFor(String familyId) {
        return locks.computeIfAbsent(familyId, k -> new Object());
    }
}
