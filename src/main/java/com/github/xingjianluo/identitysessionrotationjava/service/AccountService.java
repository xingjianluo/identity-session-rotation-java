package com.github.xingjianluo.identitysessionrotationjava.service;

import com.github.xingjianluo.identitysessionrotationjava.domain.Account;
import com.github.xingjianluo.identitysessionrotationjava.domain.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.domain.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.domain.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.error.AuthException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.store.AccountStore;
import com.github.xingjianluo.identitysessionrotationjava.store.AuditStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

/**
 * 账户自助管理（改密）与管理员操作（启停）。
 * 两类写操作都会级联撤销相关会话，使此前签发的访问/刷新令牌立即失效。
 */
@Service
public class AccountService {

    private static final Logger log = LoggerFactory.getLogger(AccountService.class);

    private final AccountStore accountStore;
    private final AuditStore auditStore;
    private final PasswordEncoder passwordEncoder;
    private final SessionRevocationService revocationService;

    public AccountService(AccountStore accountStore,
                          AuditStore auditStore,
                          PasswordEncoder passwordEncoder,
                          SessionRevocationService revocationService) {
        this.accountStore = accountStore;
        this.auditStore = auditStore;
        this.passwordEncoder = passwordEncoder;
        this.revocationService = revocationService;
    }

    /** 修改密码：校验原密码后更新哈希，并撤销该账户全部会话链。 */
    public void changePassword(String username, String oldPassword, String newPassword) {
        if (newPassword == null || newPassword.length() < 8) {
            throw new AuthException(ErrorCode.BAD_REQUEST, "新密码长度至少 8 位");
        }
        Account account = accountStore.findByUsername(username)
                .orElseThrow(() -> new AuthException(ErrorCode.INVALID_CREDENTIALS));
        if (!passwordEncoder.matches(oldPassword, account.getPasswordHash())) {
            auditStore.record(AuditEventType.LOGIN_FAILURE, username, null,
                    "reason=change_password_old_mismatch");
            log.info("改密判定 username={} => 拒绝: 原密码不正确", username);
            throw new AuthException(ErrorCode.OLD_PASSWORD_INCORRECT);
        }

        account.setPasswordHash(passwordEncoder.encode(newPassword));
        int revoked = revocationService.revokeAllForUser(username,
                RevocationReason.PASSWORD_CHANGED, "密码变更，撤销全部会话");
        auditStore.record(AuditEventType.PASSWORD_CHANGED, username, null,
                "撤销会话链数量=" + revoked);
        log.info("密码变更成功 username={} 已撤销会话链 {} 条，旧令牌立即失效", username, revoked);
    }

    /** 管理员启用/停用账户；停用时撤销该账户全部会话链。 */
    public void setStatus(String operator, String username, boolean active) {
        Account account = accountStore.findByUsername(username)
                .orElseThrow(() -> new AuthException(ErrorCode.ACCOUNT_NOT_FOUND));
        AccountStatus newStatus = active ? AccountStatus.ACTIVE : AccountStatus.DISABLED;
        account.setStatus(newStatus);

        if (!active) {
            int revoked = revocationService.revokeAllForUser(username,
                    RevocationReason.ACCOUNT_DISABLED,
                    "管理员 " + operator + " 停用账户");
            auditStore.record(AuditEventType.ACCOUNT_DISABLED, username, null,
                    "operator=" + operator + ", 撤销会话链数量=" + revoked);
            log.info("账户停用 operator={} username={} 撤销会话链 {} 条", operator, username, revoked);
        } else {
            auditStore.record(AuditEventType.ACCOUNT_ENABLED, username, null,
                    "operator=" + operator);
            log.info("账户启用 operator={} username={}", operator, username);
        }
    }
}
