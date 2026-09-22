package com.github.xingjianluo.identitysessionrotationjava.token;

import com.github.xingjianluo.identitysessionrotationjava.account.Account;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountRepository;
import com.github.xingjianluo.identitysessionrotationjava.account.AccountStatus;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditEventType;
import com.github.xingjianluo.identitysessionrotationjava.audit.AuditService;
import com.github.xingjianluo.identitysessionrotationjava.config.SecurityProperties;
import com.github.xingjianluo.identitysessionrotationjava.error.ApiException;
import com.github.xingjianluo.identitysessionrotationjava.error.ErrorCode;
import com.github.xingjianluo.identitysessionrotationjava.session.RevocationReason;
import com.github.xingjianluo.identitysessionrotationjava.session.Session;
import com.github.xingjianluo.identitysessionrotationjava.session.SessionStatus;
import com.github.xingjianluo.identitysessionrotationjava.session.SessionStore;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Local session & token service.
 *
 * <h2>Token model</h2>
 * Tokens are opaque random strings kept only server side:
 * <ul>
 *   <li>each access token points to one session (it is <em>bound</em> to it);</li>
 *   <li>each refresh token is a one-time entry carrying its own expiry;</li>
 *   <li>all tokens of a login share one {@link Session} (the rotation chain).</li>
 * </ul>
 *
 * <h2>Rotation & reuse detection</h2>
 * Refresh tokens are consumed <em>atomically</em> via per-entry locks, so
 * concurrent refreshes of the same token produce exactly one successor; the
 * losers get REFRESH_TOKEN_RACE (HTTP 409) and the winner's chain is kept.
 * A consumed token presented again after the configurable grace window is a
 * replay: the whole session chain is revoked with reason
 * REFRESH_TOKEN_REUSE_DETECTED and the request rejected with
 * REFRESH_TOKEN_REUSED.
 *
 * <h2>Stable rejection taxonomy</h2>
 * Access validation distinguishes, in decision order:
 * TOKEN_INVALID &rarr; SESSION_REVOKED (reason attached) &rarr;
 * ACCOUNT_STATE_INVALID &rarr; TOKEN_EXPIRED &rarr; success.
 */
@Service
public class TokenService {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final AccountRepository accountRepository;
    private final SessionStore sessionStore;
    private final AuditService auditService;
    private final SecurityProperties properties;
    private final Clock clock;

    private final ConcurrentMap<String, AccessEntry> accessTokens = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, RefreshEntry> refreshTokens = new ConcurrentHashMap<>();

    public TokenService(AccountRepository accountRepository,
                        SessionStore sessionStore,
                        AuditService auditService,
                        SecurityProperties properties,
                        Clock clock) {
        this.accountRepository = accountRepository;
        this.sessionStore = sessionStore;
        this.auditService = auditService;
        this.properties = properties;
        this.clock = clock;
    }

    /** One access token and its bound session. */
    private static final class AccessEntry {
        final String sessionId;
        final Instant expiresAt;

        AccessEntry(String sessionId, Instant expiresAt) {
            this.sessionId = sessionId;
            this.expiresAt = expiresAt;
        }
    }

    /** One refresh token: the current usable link, or a consumed historical link. */
    private static final class RefreshEntry {
        final String sessionId;
        final Instant expiresAt;
        volatile boolean consumed;
        volatile Instant consumedAt;

        RefreshEntry(String sessionId, Instant expiresAt) {
            this.sessionId = sessionId;
            this.expiresAt = expiresAt;
        }
    }

    /** Authenticated caller context derived from a valid access token. */
    public record AuthContext(String accountId, String sessionId,
                              Set<String> roles, Set<String> permissions) {
    }

    /** Creates a new session and returns the first token pair of its chain. */
    public TokenPair issueSession(Account account) {
        Instant now = clock.instant();
        Session session = new Session(
                newTokenId("s"), account.id(), account.tokenVersion(),
                now, now.plusSeconds(properties.getRefreshTokenTtlSeconds()));
        sessionStore.save(session);
        String access = newTokenId("at");
        String refresh = newTokenId("rt");
        accessTokens.put(access, new AccessEntry(session.id(),
                now.plusSeconds(properties.getAccessTokenTtlSeconds())));
        refreshTokens.put(refresh, new RefreshEntry(session.id(),
                now.plusSeconds(properties.getRefreshTokenTtlSeconds())));
        return new TokenPair(access, refresh, properties.getAccessTokenTtlSeconds());
    }

    /**
     * Atomically consumes the presented refresh token and issues the next
     * pair in the same chain. Presenting a consumed token triggers reuse
     * detection: chain revocation + REFRESH_TOKEN_REUSED.
     */
    public TokenPair rotate(String refreshToken) {
        if (refreshToken == null || refreshToken.isBlank()) {
            throw refreshFailure(null, null, "missing_refresh_token", ErrorCode.REFRESH_TOKEN_INVALID);
        }
        RefreshEntry entry = refreshTokens.get(refreshToken);
        if (entry == null) {
            throw refreshFailure(null, null,
                    "reason=unknown_refresh_token", ErrorCode.REFRESH_TOKEN_INVALID);
        }
        // Per-entry lock: exactly one of N concurrent refreshes succeeds.
        synchronized (entry) {
            Instant now = clock.instant();
            Session session = sessionStore.findById(entry.sessionId).orElse(null);
            if (entry.consumed) {
                return handleReplay(entry, session);
            }
            if (clock.instant().isAfter(entry.expiresAt)
                    || session == null
                    || session.status() != SessionStatus.ACTIVE) {
                return handleDeadChain(entry, session);
            }
            Account account = accountRepository.findById(session.accountId()).orElse(null);
            if (account == null || account.status() != AccountStatus.ACTIVE) {
                entry.consumed = true;
                entry.consumedAt = now;
                sessionStore.revokeOne(session.id(), RevocationReason.ACCOUNT_DISABLED);
                throw refreshFailure(account == null ? null : account.id(), session.id(),
                        "reason=account_state_invalid", ErrorCode.ACCOUNT_STATE_INVALID);
            }
            // Commit: consume exactly this one link, mint its successor.
            entry.consumed = true;
            entry.consumedAt = now;
            String access = newTokenId("at");
            String nextRefresh = newTokenId("rt");
            accessTokens.put(access, new AccessEntry(session.id(),
                    now.plusSeconds(properties.getAccessTokenTtlSeconds())));
            refreshTokens.put(nextRefresh, new RefreshEntry(session.id(), entry.expiresAt));
            auditService.record(AuditEventType.TOKEN_REFRESHED,
                    account.id(), session.id(), "rotation=success");
            return new TokenPair(access, nextRefresh, properties.getAccessTokenTtlSeconds());
        }
    }

    private TokenPair handleReplay(RefreshEntry entry, Session session) {
        String accountId = session == null ? null : session.accountId();
        String sessionId = session == null ? null : session.id();
        Instant now = clock.instant();
        boolean withinGrace = entry.consumedAt != null
                && !now.isAfter(entry.consumedAt
                        .plusSeconds(properties.getRefreshReuseGraceSeconds()));
        if (withinGrace) {
            // A repeat inside the grace window is indistinguishable from a
            // benign client retrying while a rotation is in flight: reject it
            // as a lost race but leave the winner's successor chain intact.
            auditService.record(AuditEventType.REFRESH_FAILURE, accountId, sessionId,
                    "reason=concurrent_rotation_race");
            throw new ApiException(ErrorCode.REFRESH_TOKEN_RACE,
                    "refresh token already used by a concurrent request");
        }
        if (session != null && session.status() == SessionStatus.ACTIVE) {
            // A consumed link reappearing after the grace window while the
            // chain is still active means the chain has leaked: burn it.
            sessionStore.revokeOne(session.id(), RevocationReason.REFRESH_TOKEN_REUSE_DETECTED);
        }
        auditService.record(AuditEventType.REFRESH_TOKEN_REUSE_DETECTED,
                accountId, sessionId, "consumed_refresh_token_presented_after_grace_window");
        throw refreshFailure(accountId, sessionId,
                "reason=refresh_token_reused", ErrorCode.REFRESH_TOKEN_REUSED);
    }

    private TokenPair handleDeadChain(RefreshEntry entry, Session session) {
        String accountId = session == null ? null : session.accountId();
        String sessionId = session == null ? null : session.id();
        Instant now = clock.instant();
        if (session != null && session.status() == SessionStatus.REVOKED) {
            auditService.record(AuditEventType.REFRESH_FAILURE, accountId, sessionId,
                    "reason=session_revoked:" + session.revocationReason());
            throw new ApiException(ErrorCode.SESSION_REVOKED,
                    "session revoked: " + session.revocationReason());
        }
        if (now.isAfter(entry.expiresAt)) {
            throw refreshFailure(accountId, sessionId,
                    "reason=refresh_token_expired", ErrorCode.REFRESH_TOKEN_EXPIRED);
        }
        throw refreshFailure(accountId, sessionId,
                "reason=session_unknown", ErrorCode.REFRESH_TOKEN_INVALID);
    }

    /**
     * Validates an access token, returning the authenticated context.
     * Decision order: unknown token &rarr; revoked session &rarr;
     * invalid account state &rarr; expired token &rarr; success, so the
     * caller always receives the most specific stable error category.
     */
    public AuthContext authenticate(String accessToken) {
        if (accessToken == null || accessToken.isBlank()) {
            throw new ApiException(ErrorCode.TOKEN_INVALID, "missing access token");
        }
        AccessEntry entry = accessTokens.get(accessToken);
        if (entry == null) {
            throw new ApiException(ErrorCode.TOKEN_INVALID, "unknown access token");
        }
        Session session = sessionStore.findById(entry.sessionId)
                .orElseThrow(() -> new ApiException(ErrorCode.TOKEN_INVALID,
                        "session no longer exists"));
        if (session.status() == SessionStatus.REVOKED) {
            throw new ApiException(ErrorCode.SESSION_REVOKED,
                    "session revoked: " + session.revocationReason());
        }
        Account account = accountRepository.findById(session.accountId())
                .orElseThrow(() -> new ApiException(ErrorCode.ACCOUNT_STATE_INVALID,
                        "account no longer exists"));
        if (account.status() == AccountStatus.DISABLED) {
            throw new ApiException(ErrorCode.ACCOUNT_STATE_INVALID, "account disabled");
        }
        if (account.tokenVersion() != session.accountTokenVersion()) {
            // Password changed but the session escaped prior revocation.
            sessionStore.revokeOne(session.id(), RevocationReason.PASSWORD_CHANGED);
            throw new ApiException(ErrorCode.SESSION_REVOKED, "session revoked: PASSWORD_CHANGED");
        }
        if (clock.instant().isAfter(entry.expiresAt)) {
            throw new ApiException(ErrorCode.TOKEN_EXPIRED, "access token expired");
        }
        return new AuthContext(account.id(), session.id(),
                account.roles(), account.permissions());
    }

    /** Revokes the session bound to this access token (logout). */
    public void logout(String accessToken) {
        AccessEntry entry = accessToken == null ? null : accessTokens.get(accessToken);
        if (entry == null) {
            // Idempotent: nothing to log out.
            return;
        }
        Session session = sessionStore.findById(entry.sessionId).orElse(null);
        boolean changed = sessionStore.revokeOne(entry.sessionId, RevocationReason.LOGOUT);
        // The access token entry is intentionally retained: a later replay of
        // it must be classified as SESSION_REVOKED(LOGOUT), not as an unknown
        // token or ordinary expiry.
        if (changed && session != null) {
            auditService.record(AuditEventType.LOGOUT, session.accountId(), session.id(),
                    "reason=user_logout");
            auditService.record(AuditEventType.SESSION_REVOKED,
                    session.accountId(), session.id(), "reason=LOGOUT");
        }
    }

    private ApiException refreshFailure(String accountId, String sessionId,
                                        String detail, ErrorCode code) {
        auditService.record(AuditEventType.REFRESH_FAILURE, accountId, sessionId, detail);
        return new ApiException(code, detail);
    }

    private static String newTokenId(String prefix) {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return prefix + "_" + HexFormat.of().formatHex(bytes);
    }
}
