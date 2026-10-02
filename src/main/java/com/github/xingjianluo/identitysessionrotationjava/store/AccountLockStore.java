package com.github.xingjianluo.identitysessionrotationjava.store;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 按账户名提供互斥锁：账户级操作（新登录 + 超限淘汰、退出其他设备）串行化，
 * 保证并发登录不会冲破每账户活跃登录上限。
 */
@Component
public class AccountLockStore {

    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    public Object lockFor(String username) {
        return locks.computeIfAbsent(username.toLowerCase(), k -> new Object());
    }
}
