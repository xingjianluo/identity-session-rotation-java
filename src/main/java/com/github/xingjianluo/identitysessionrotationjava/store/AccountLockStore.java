package com.github.xingjianluo.identitysessionrotationjava.store;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 按用户名提供互斥锁对象。
 *
 * <p>登录时的「建立新会话 + 超限淘汰」在持有该账号锁的区间内完成，
 * 因此同一账号的并发登录被串行化，活跃会话数上限不会被冲破；
 * 不同账号之间完全并行。
 */
@Component
public class AccountLockStore {

    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    public Object lockFor(String username) {
        return locks.computeIfAbsent(username, k -> new Object());
    }
}
