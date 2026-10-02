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
import com.github.xingjianluo.identitysessionrotationjava.store.FamilyLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.SessionStore;
import com.github.xingjianluo.identitysessionrotationjava.web.dto.SessionInfoResponse;
import java.time.Instant;
import java.util.Comparator;
import java.util.List;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 多设备会话管理：活跃会话查看、单会话撤销、退出其他设备，
 * 以及新登录时按“最久未活跃先淘汰”执行每账户上限清理。
 *
 * <p>并发模型：
 * <ul>
 *   <li>账户级操作（新登录的建链+淘汰、退出其他设备）在 {@link AccountLockStore}
 *       的账户锁内串行，因此多个客户端几乎同时登录也不会冲破上限，
 *       留下的会话由确定性排序决定（可预期）。</li>
 *   <li>单链撤销在该 family 的锁内执行（见 {@link SessionRevocationService}），
 *       与同链刷新线性化，撤销完成后该链不可能再刷出可用新令牌。</li>
 * </ul>
 */
@Service
public class DeviceSessionService {

    private static final Logger log = LoggerFactory.getLogger(DeviceSessionService.class);

    /**
     * 淘汰排序：最久未活跃优先；lastActiveAt 相同时按登录时间；
     * 再相同按 familyId 字典序兜底，保证并发下结果确定可预期。
     */
    private static final Comparator<DeviceSession> EVICTION_ORDER =
            Comparator.comparing(DeviceSession::getLastActiveAt)
                    .thenComparing(DeviceSession::getLoginAt)
                    .thenComparing(DeviceSession::getFamilyId);

    private final DeviceSessionStore deviceSessionStore;
    private final SessionStore sessionStore;
    private final AuditStore auditStore;
    private final AccountLockStore accountLockStore;
    private final FamilyLockStore familyLockStore;
    private final SessionRevocationService revocationService;
    private final SecurityProperties properties;

    public DeviceSessionService(DeviceSessionStore deviceSessionStore,
                                SessionStore sessionStore,
                                AuditStore auditStore,
                                AccountLockStore accountLockStore,
                                FamilyLockStore familyLockStore,
                                SessionRevocationService revocationService,
                                SecurityProperties properties) {
        this.deviceSessionStore = deviceSessionStore;
        this.sessionStore = sessionStore;
        this.auditStore = auditStore;
        this.accountLockStore = accountLockStore;
        this.familyLockStore = familyLockStore;
        this.revocationService = revocationService;
        this.properties = properties;
    }

    /** 新登录成功后登记设备会话。 */
    public void register(DeviceSession device) {
        deviceSessionStore.save(device);
        log.info("设备会话登记 username={} familyId={} clientId={} loginAt={}",
                device.getUsername(), device.getFamilyId(), device.getClientId(),
                device.getLoginAt());
    }

    /**
     * 新登录后执行每账户活跃登录上限清理。必须在账户锁内调用（见 {@link #withAccountLock}）。
     *
     * <p>规则：活跃会话数超过 {@code app.security.max-concurrent-sessions} 时，
     * 按 {@link #EVICTION_ORDER} 淘汰最久未活跃的若干条；本次新登录所在链
     * （{@code newFamilyId}）保证保留。被淘汰链立即整链撤销，之后其任何
     * access/refresh 令牌都不能再成功。
     *
     * @return 实际被淘汰的设备会话
     */
    public List<DeviceSession> enforceLimitAfterLogin(String username, String newFamilyId) {
        int limit = properties.getMaxConcurrentSessions();
        if (limit <= 0) {
            return List.of();
        }
        List<DeviceSession> active = activeDevices(username);
        if (active.size() <= limit) {
            return List.of();
        }
        int excess = active.size() - limit;
        List<DeviceSession> victims = active.stream()
                .sorted(EVICTION_ORDER)
                .filter(d -> !d.getFamilyId().equals(newFamilyId))
                .limit(excess)
                .toList();

        for (DeviceSession victim : victims) {
            revocationService.revokeFamily(victim.getFamilyId(),
                    RevocationReason.MAX_SESSIONS_EVICTED, username,
                    "活跃登录数超过上限 " + limit + "，最久未活跃会话被清理");
            deviceSessionStore.remove(victim.getFamilyId());
            auditStore.record(AuditEventType.SESSION_EVICTED, username,
                    victim.getFamilyId(),
                    "basis=max_concurrent_sessions, limit=" + limit
                            + ", lastActiveAt=" + victim.getLastActiveAt()
                            + ", clientId=" + victim.getClientId());
            log.info("超限淘汰设备会话 username={} familyId={} lastActiveAt={} clientId={}",
                    username, victim.getFamilyId(), victim.getLastActiveAt(),
                    victim.getClientId());
        }
        return victims;
    }

    /** 账户级串行化执行：并发登录 / 退出其他设备据此线性化。 */
    public void withAccountLock(String username, Runnable action) {
        synchronized (accountLockStore.lockFor(username)) {
            action.run();
        }
    }

    /** 列出账户当前活跃的设备登录（不含已撤销），最近活跃倒序。 */
    public List<SessionInfoResponse> listSessions(String username, String currentFamilyId) {
        List<SessionInfoResponse> result = activeDevices(username).stream()
                .sorted(Comparator.comparing(DeviceSession::getLastActiveAt).reversed())
                .map(d -> new SessionInfoResponse(
                        d.getFamilyId(),
                        d.getClientId(),
                        d.getClientName(),
                        d.getUserAgent(),
                        d.getIp(),
                        d.getLoginAt(),
                        d.getLastActiveAt(),
                        java.util.Objects.equals(d.getFamilyId(), currentFamilyId)))
                .toList();
        auditStore.record(AuditEventType.SESSION_LISTED, username, currentFamilyId,
                "活跃会话数=" + result.size());
        log.info("会话查看 username={} 活跃会话数={}", username, result.size());
        return result;
    }

    /**
     * 撤销指定的单个设备会话。只能撤销自己名下的会话：
     * 目标不存在 / 不属于当前账户 → {@code session_not_found}（不泄露目标是否存在）。
     */
    public void revokeSession(String username, String familyId) {
        if (familyId == null || familyId.isBlank()) {
            throw new AuthException(ErrorCode.BAD_REQUEST, "缺少会话标识");
        }
        DeviceSession target = deviceSessionStore.findByFamily(familyId).orElse(null);
        if (target == null || !target.getUsername().equalsIgnoreCase(username)) {
            auditStore.record(AuditEventType.SESSION_REVOKE_ONE, username, familyId,
                    "result=not_found_or_not_owner");
            log.info("单会话撤销 username={} familyId={} => 拒绝: 会话不存在或不属于该账户",
                    username, familyId);
            throw new AuthException(ErrorCode.SESSION_NOT_FOUND);
        }

        boolean changed = revocationService.revokeFamily(familyId,
                RevocationReason.DEVICE_REVOKED, username, "用户单独撤销设备会话");
        deviceSessionStore.remove(familyId);
        auditStore.record(AuditEventType.SESSION_REVOKE_ONE, username, familyId,
                "result=" + (changed ? "revoked" : "already_revoked")
                        + ", clientId=" + target.getClientId());
        log.info("单会话撤销成功 username={} familyId={} clientId={} changed={}",
                username, familyId, target.getClientId(), changed);
    }

    /**
     * 退出其他所有设备：撤销除当前会话外该账户的全部活跃会话。
     * 在账户锁内执行，与并发登录线性化；返回实际撤销数量。
     */
    public int revokeOtherSessions(String username, String currentFamilyId) {
        int[] revoked = {0};
        withAccountLock(username, () -> {
            List<DeviceSession> others = activeDevices(username).stream()
                    .filter(d -> !d.getFamilyId().equals(currentFamilyId))
                    .toList();
            for (DeviceSession other : others) {
                revocationService.revokeFamily(other.getFamilyId(),
                        RevocationReason.OTHER_DEVICES_LOGOUT, username,
                        "用户执行退出其他所有设备，保留 familyId=" + currentFamilyId);
                deviceSessionStore.remove(other.getFamilyId());
                revoked[0]++;
                log.info("退出其他设备 username={} revokedFamilyId={} clientId={}",
                        username, other.getFamilyId(), other.getClientId());
            }
            auditStore.record(AuditEventType.SESSION_REVOKE_OTHERS, username,
                    currentFamilyId, "撤销会话数=" + revoked[0]);
        });
        log.info("退出其他所有设备完成 username={} currentFamilyId={} 撤销数={}",
                username, currentFamilyId, revoked[0]);
        return revoked[0];
    }

    /** 刷新/访问活动推进最近活跃时间；未知或已撤销链静默忽略。 */
    public void touch(String familyId) {
        if (familyId == null) {
            return;
        }
        deviceSessionStore.findByFamily(familyId).ifPresent(d -> d.touch(Instant.now()));
    }

    /** 账户名下仍活跃（family 未被整链撤销）的设备会话。 */
    private List<DeviceSession> activeDevices(String username) {
        return deviceSessionStore.findByUsername(username).stream()
                .filter(d -> sessionStore.isFamilyActive(d.getFamilyId()))
                .toList();
    }
}
