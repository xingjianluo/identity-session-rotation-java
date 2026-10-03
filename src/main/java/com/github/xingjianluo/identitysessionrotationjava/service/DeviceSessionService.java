package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.DeviceSessionStore;
import java.time.Instant;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 多设备会话管理：查看活跃登录、撤销单个登录、退出其他设备、登录数上限淘汰。
 *
 * <p>撤销语义与既有撤销链路一致（会话 + 链上令牌立即失效，原因可解释），
 * 只作用于被点名的 family，其他登录不受影响。
 */
@Service
public class DeviceSessionService {

    private static final Logger log = LoggerFactory.getLogger(DeviceSessionService.class);

    private final DeviceSessionStore deviceSessionStore;
    private final SessionRevocationService revocationService;
    private final AuditStore auditStore;
    private final SecurityProperties properties;
    private final AccountLockStore accountLockStore;

    public DeviceSessionService(DeviceSessionStore deviceSessionStore,
                                SessionRevocationService revocationService,
                                AuditStore auditStore,
                                SecurityProperties properties,
                                AccountLockStore accountLockStore) {
        this.deviceSessionStore = deviceSessionStore;
        this.revocationService = revocationService;
        this.auditStore = auditStore;
        this.properties = properties;
        this.accountLockStore = accountLockStore;
    }

    /** 登录成功时登记一个设备登录。 */
    public DeviceSession registerLogin(String username, String familyId, String client) {
        DeviceSession session = new DeviceSession(familyId, username,
                client == null || client.isBlank() ? "unknown" : client.trim(),
                Instant.now());
        deviceSessionStore.save(session);
        return session;
    }

    /**
     * 刷新或访问成功时更新最近活跃时间。
     *
     * <p>与登录流程使用同一把账号锁串行化：登录的「登记新登录 → 上限淘汰」窗口内
     * 不会插入他设备的活跃时间更新，淘汰排序快照保持稳定，结果可预期。
     * 锁内复查活跃状态：若该登录恰好在等锁期间被淘汰，则不再复活它。
     */
    public void touch(String username, String familyId) {
        synchronized (accountLockStore.lockFor(username)) {
            deviceSessionStore.findByFamilyId(familyId)
                    .filter(DeviceSession::isActive)
                    .ifPresent(s -> s.touch(Instant.now()));
        }
    }

    /** 列出某账号当前活跃登录（按最久未活动升序，当前登录由调用方标记）。 */
    public List<DeviceSession> listActive(String username) {
        List<DeviceSession> sessions = deviceSessionStore.findActiveByUsername(username);
        auditStore.record(AuditEventType.DEVICE_SESSIONS_LISTED, username, null,
                "活跃登录数=" + sessions.size());
        log.info("查看活跃登录 username={} 活跃登录数={}", username, sessions.size());
        return sessions;
    }

    /**
     * 撤销指定的一个登录（仅限本人）。立即生效，不影响其他登录。
     */
    public void revokeOne(String username, String familyId) {
        DeviceSession target = deviceSessionStore.findByFamilyId(familyId)
                .filter(s -> s.getUsername().equals(username))
                .orElseThrow(() -> new AuthException(ErrorCode.SESSION_NOT_FOUND));
        revocationService.revokeFamily(familyId, RevocationReason.DEVICE_REVOKED,
                username, "用户撤销单个设备登录 client=" + target.getClient());
        auditStore.record(AuditEventType.DEVICE_SESSION_REVOKED, username, familyId,
                "client=" + target.getClient());
        log.info("撤销单个设备登录 username={} familyId={} client={}",
                username, familyId, target.getClient());
    }

    /**
     * 退出其他所有设备：撤销除 currentFamilyId 之外的全部活跃登录。
     *
     * @return 被撤销的登录数
     */
    public int revokeOthers(String username, String currentFamilyId) {
        List<DeviceSession> others = deviceSessionStore.findActiveByUsername(username)
                .stream()
                .filter(s -> !s.getFamilyId().equals(currentFamilyId))
                .toList();
        int revoked = 0;
        for (DeviceSession other : others) {
            revocationService.revokeFamily(other.getFamilyId(),
                    RevocationReason.DEVICE_REVOKED, username,
                    "退出其他设备 client=" + other.getClient());
            revoked++;
        }
        auditStore.record(AuditEventType.OTHER_SESSIONS_REVOKED, username,
                currentFamilyId, "撤销其他登录数=" + revoked);
        log.info("退出其他设备 username={} 保留 familyId={} 撤销其他登录数={}",
                username, currentFamilyId, revoked);
        return revoked;
    }

    /**
     * 登录数上限淘汰：活跃登录数超过配置上限时，按“最久未活动最先清掉”
     * 撤销多余部分（并列按登录时间、familyId 确定次序，结果可预期）。
     *
     * <p><b>新登录豁免</b>：触发本次淘汰的 {@code protectedFamilyId}（本次刚登录
     * 的设备）永远不会被它自己触发的淘汰清掉——它在登录返回后必须立即可用。
     * 被淘汰的只能是<b>本次登录之前就已存在</b>的登录。
     *
     * <p><b>边界语义</b>：上限配置为 {@code <=0}（如 0）或小于当前活跃数时，
     * 有效上限按 {@code max(1, 配置值)} 解释——每次登录后至少保留这一次新登录，
     * 不会出现“所有设备都登录成功但令牌全部立刻失效”。
     *
     * <p>调用方必须持有该账号的互斥锁（见 AuthService 登录流程），
     * 以保证并发登录、他设备并发访问/刷新不会冲破上限或改写淘汰次序。
     *
     * @param username           账号
     * @param protectedFamilyId  本次新登录的 familyId，永不参与本次淘汰
     */
    public void enforceLimit(String username, String protectedFamilyId) {
        int configured = properties.getMaxActiveSessionsPerAccount();
        int max = Math.max(1, configured);
        List<DeviceSession> active = deviceSessionStore.findActiveByUsername(username);
        // 只从“本次登录之前已存在”的登录中选淘汰对象，新登录豁免
        List<DeviceSession> candidates = active.stream()
                .filter(s -> !s.getFamilyId().equals(protectedFamilyId))
                .toList();
        int excess = active.size() - max;
        int victimCount = Math.max(0, Math.min(excess, candidates.size()));
        for (int i = 0; i < victimCount; i++) {
            DeviceSession victim = candidates.get(i);
            revocationService.revokeFamily(victim.getFamilyId(),
                    RevocationReason.SESSION_LIMIT_EVICTED, username,
                    "超出同时在线上限 configuredMax=" + configured + ", effectiveMax=" + max
                            + ", 淘汰最久未活动的既有登录 client=" + victim.getClient()
                            + ", lastActiveAt=" + victim.getLastActiveAt());
            auditStore.record(AuditEventType.SESSION_EVICTED_LIMIT, username,
                    victim.getFamilyId(),
                    "configuredMax=" + configured + ", effectiveMax=" + max
                            + ", client=" + victim.getClient()
                            + ", lastActiveAt=" + victim.getLastActiveAt());
            log.info("超限淘汰 username={} familyId={} client={} lastActiveAt={} "
                            + "configuredMax={} effectiveMax={} protectedFamilyId={}",
                    username, victim.getFamilyId(), victim.getClient(),
                    victim.getLastActiveAt(), configured, max, protectedFamilyId);
        }
        if (configured <= 0) {
            log.info("上限边界处理 username={} configuredMax={} <=0, 有效上限按 1 解释, "
                            + "本次新登录 familyId={} 保留, 淘汰既有登录数={}",
                    username, configured, protectedFamilyId, victimCount);
        }
    }
}
