package com.github.xingjianluo.identitysessionrotationjava.store;

import java.util.concurrent.ConcurrentHashMap;
import org.springframework.stereotype.Component;

/**
 * 按用户名提供互斥锁对象。
 *
 * <p>同一账号的三类操作在该锁内串行化：
 * <ol>
 *   <li>登录的「建立新会话 + 上限淘汰」：并发登录被串行化，活跃会话数上限
 *       不会被冲破，且触发淘汰的新登录不会被自己清掉；</li>
 *   <li>访问/刷新成功后的「最近活跃时间」更新：不会插入登录的淘汰窗口、
 *       把刚登录的设备推到淘汰队首；</li>
 * </ol>
 * 不同账号之间完全并行。
 */
@Component
public class AccountLockStore {

    private final ConcurrentHashMap<String, Object> locks = new ConcurrentHashMap<>();

    public Object lockFor(String username) {
        return locks.computeIfAbsent(username, k -> new Object());
    }
}
