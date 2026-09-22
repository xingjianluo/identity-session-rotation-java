package com.github.xingjianluo.identitysessionrotationjava.account;

import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditService;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.session.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.session.Session;
import com.github.xingjianluo.identitysessionrotationjava.session.SessionStore;
import org.springframework.stereotype.Service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HexFormat;
import java.util.List;

/**
 * Login verification and account lifecycle operations.
 *
 * <p>Account-existence safety: {@link #verifyLogin} performs the password
 * hash unconditionally and maps every failure (unknown user, wrong password,
 * disabled account) to the same external {@code INVALID_CREDENTIALS} error.
 *
 * <p>Immediate invalidation: password change and disable bump state
 * (password also bumps {@code tokenVersion}) and synchronously revoke every
 * existing session of the account, so previously issued tokens stop working
 * on the very next request.
 */
@Service
public class AccountService {

    private final AccountRepository accountRepository;
    private final SessionStore sessionStore;
    private final AuditService auditService;

    public AccountService(AccountRepository accountRepository,
                          SessionStore sessionStore,
                          AuditService auditService) {
        this.accountRepository = accountRepository;
        this.sessionStore = sessionStore;
        this.auditService = auditService;
    }

    /**
     * Verifies credentials. Never reveals whether the account exists:
     * unknown user, wrong password and disabled account all raise
     * {@code INVALID_CREDENTIALS}. The internal failure category is recorded
     * in the audit log only.
     */
    public Account verifyLogin(String username, String password) {
        byte[] presentedHash = hash(password == null ? "" : password);
        Account account = accountRepository.findByUsername(username).orElse(null);
        if (account == null) {
            auditService.record(AuditEventType.LOGIN_FAILURE, null, null,
                    "username=" + username + " reason=unknown_username");
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, "invalid username or password");
        }
        if (!constantTimeEquals(presentedHash,
                HexFormat.of().parseHex(account.passwordHash()))) {
            auditService.record(AuditEventType.LOGIN_FAILURE, account.id(), null,
                    "username=" + username + " reason=bad_password");
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, "invalid username or password");
        }
        if (account.status() == AccountStatus.DISABLED) {
            auditService.record(AuditEventType.LOGIN_FAILURE, account.id(), null,
                    "username=" + username + " reason=account_disabled");
            throw new ApiException(ErrorCode.INVALID_CREDENTIALS, "invalid username or password");
        }
        auditService.record(AuditEventType.LOGIN_SUCCESS, account.id(), null,
                "username=" + username);
        return account;
    }

    /**
     * Changes the password, bumps the token version and immediately revokes
     * every existing session with reason PASSWORD_CHANGED.
     */
    public void changePassword(String accountId, String newPassword) {
        Account account = accountRepository.findById(accountId)
                .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID,
                        "account no longer exists"));
        account.changePassword(HexFormat.of().formatHex(hash(newPassword)));
        List<Session> revoked =
                sessionStore.revokeAllForAccount(accountId, RevocationReason.PASSWORD_CHANGED);
        auditService.record(AuditEventType.PASSWORD_CHANGED, accountId, null,
                "revokedSessions=" + revoked.size());
        for (Session s : revoked) {
            auditService.record(AuditEventType.SESSION_REVOKED, accountId, s.id(),
                    "reason=PASSWORD_CHANGED");
        }
    }

    /**
     * Disables the account and immediately revokes its sessions with reason
     * ACCOUNT_DISABLED; subsequent requests on surviving tokens fail with
     * ACCOUNT_STATE_INVALID / SESSION_REVOKED.
     */
    public void disable(String accountId) {
        Account account = accountRepository.findById(accountId)
                .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID,
                        "account no longer exists"));
        account.disable();
        List<Session> revoked =
                sessionStore.revokeAllForAccount(accountId, RevocationReason.ACCOUNT_DISABLED);
        for (Session s : revoked) {
            auditService.record(AuditEventType.SESSION_REVOKED, accountId, s.id(),
                    "reason=ACCOUNT_DISABLED");
        }
    }

    /** Demo-grade local password hash: SHA-256 hex. Not for production use. */
    public static byte[] hash(String raw) {
        try {
            return MessageDigest.getInstance("SHA-256")
                    .digest(raw.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 unavailable", e);
        }
    }

    private static boolean constantTimeEquals(byte[] a, byte[] b) {
        return MessageDigest.isEqual(a, b);
    }
}
