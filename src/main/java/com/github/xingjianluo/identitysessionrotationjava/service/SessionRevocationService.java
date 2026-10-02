package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.domain.AccessTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.RefreshTokenInfo;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.domain.Session;
import com.github.xingjianluo.identitysessionrotationjava.store.AccessTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import com.github.xingjianluo.identitysessionrotationjava.store.DeviceSessionStore;
import com.github.xingjianluo.identitysessionrotationjava.store.FamilyLockStore;
import com.github.xingjianluo.identitysessionrotationjava.store.RefreshTokenStore;
import com.github.xingjianluo.identitysessionrotationjava.store.SessionStore;
import java.util.LinkedHashSet;
import java.util.Set;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 会话链撤销：撤销动作对「会话 + 链上全部访问令牌 + 链上全部刷新令牌」生效，
 * 保证撤销后此前签发的令牌立即失败，并保留可解释的撤销原因。
 */
@Service
public class SessionRevocationService {

    private static final Logger log = LoggerFactory.getLogger(SessionRevocationService.class);

    private final SessionStore sessionStore;
    private final AccessTokenStore accessTokenStore;
    private final RefreshTokenStore refreshTokenStore;
    private final AuditStore auditStore;
    private final FamilyLockStore familyLockStore;
    private final DeviceSessionStore deviceSessionStore;

    public SessionRevocationService(SessionStore sessionStore,
                                    AccessTokenStore accessTokenStore,
                                    RefreshTokenStore refreshTokenStore,
                                    AuditStore auditStore,
                                    FamilyLockStore familyLockStore,
                                    DeviceSessionStore deviceSessionStore) {
        this.sessionStore = sessionStore;
        this.accessTokenStore = accessTokenStore;
        this.refreshTokenStore = refreshTokenStore;
        this.auditStore = auditStore;
        this.familyLockStore = familyLockStore;
        this.deviceSessionStore = deviceSessionStore;
    }

    /**
     * 撤销单条会话链（family）。幂等：重复撤销不会覆盖首次原因。
     *
     * <p>与刷新流程共用同一把 family 锁：撤销在锁内完成，保证撤销返回后
     * 该链上的并发刷新要么已完成（其新令牌随后被此处一并撤销）、
     * 要么在进入锁后看到已撤销状态而失败，不会出现“撤销完成却又换到新令牌”。
     *
     * @return 是否发生了新的撤销（此前未被撤销）
     */
    public boolean revokeFamily(String familyId, RevocationReason reason,
                                String username, String detail) {
        synchronized (familyLockStore.lockFor(familyId)) {
            boolean changed = false;
            for (Session session : sessionStore.findByFamily(familyId)) {
                if (!session.isRevoked()) {
                    session.markRevoked(reason);
                    changed = true;
                }
            }
            for (AccessTokenInfo token : accessTokenStore.findByFamily(familyId)) {
                token.markRevoked();
            }
            for (RefreshTokenInfo token : refreshTokenStore.findByFamily(familyId)) {
                token.markRevoked();
            }
            // family 级别原因：整链撤销的权威原因（优先于单会话原因，终态取首次）
            sessionStore.markFamilyRevoked(familyId, reason);
            // 设备登录视图同步失效（多设备列表不再展示）
            deviceSessionStore.findByFamilyId(familyId)
                    .ifPresent(ds -> ds.markInactive());
            if (changed) {
                log.info("会话链撤销 familyId={} username={} reason={} detail={}",
                        familyId, username, reason, detail);
                auditStore.record(AuditEventType.SESSION_REVOKED, username, familyId,
                        "reason=" + reason + (detail != null ? ", " + detail : ""));
            }
            return changed;
        }
    }

    /**
     * 撤销一个账户的全部会话链（用于改密、账户停用）。
     *
     * @return 被撤销的链数量
     */
    public int revokeAllForUser(String username, RevocationReason reason, String detail) {
        Set<String> families = new LinkedHashSet<>();
        for (Session session : sessionStore.findByUsername(username)) {
            families.add(session.getFamilyId());
        }
        int count = 0;
        for (String familyId : families) {
            if (revokeFamily(familyId, reason, username, detail)) {
                count++;
            }
        }
        return count;
    }
}
