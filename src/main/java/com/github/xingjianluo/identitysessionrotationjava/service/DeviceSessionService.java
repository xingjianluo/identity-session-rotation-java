package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.DeviceSession;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
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

    public DeviceSessionService(DeviceSessionStore deviceSessionStore,
                                SessionRevocationService revocationService,
                                AuditStore auditStore,
                                SecurityProperties properties) {
        this.deviceSessionStore = deviceSessionStore;
        this.revocationService = revocationService;
        this.auditStore = auditStore;
        this.properties = properties;
    }

    /** 登录成功时登记一个设备登录。 */
    public DeviceSession registerLogin(String username, String familyId, String client) {
        DeviceSession session = new DeviceSession(familyId, username,
                client == null || client.isBlank() ? "unknown" : client.trim(),
                Instant.now());
        deviceSessionStore.save(session);
        return session;
    }

    /** 刷新或访问成功时更新最近活跃时间。 */
    public void touch(String familyId) {
        deviceSessionStore.findByFamilyId(familyId)
                .filter(DeviceSession::isActive)
                .ifPresent(s -> s.touch(Instant.now()));
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
     * <p>调用方必须持有该账号的互斥锁（见 AuthService 登录流程），
     * 以保证并发登录不会冲破上限。
     */
    public void enforceLimit(String username) {
        int max = properties.getMaxActiveSessionsPerAccount();
        List<DeviceSession> active = deviceSessionStore.findActiveByUsername(username);
        int excess = active.size() - max;
        for (int i = 0; i < excess; i++) {
            DeviceSession victim = active.get(i);
            revocationService.revokeFamily(victim.getFamilyId(),
                    RevocationReason.SESSION_LIMIT_EVICTED, username,
                    "超出同时在线上限 max=" + max + ", 淘汰最久未活动登录 client="
                            + victim.getClient() + ", lastActiveAt=" + victim.getLastActiveAt());
            auditStore.record(AuditEventType.SESSION_EVICTED_LIMIT, username,
                    victim.getFamilyId(),
                    "max=" + max + ", client=" + victim.getClient()
                            + ", lastActiveAt=" + victim.getLastActiveAt());
            log.info("超限淘汰 username={} familyId={} client={} lastActiveAt={} max={}",
                    username, victim.getFamilyId(), victim.getClient(),
                    victim.getLastActiveAt(), max);
        }
    }
}
