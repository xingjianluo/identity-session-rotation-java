package com.github.xingjianluo.identitysessionrotationjava.session;

import java.time.Instant;

/**
 * A session chains all tokens derived from one login. Revoking the session
 * invalidates the whole chain at once; the revocation reason is retained so
 * it stays distinguishable from ordinary expiry.
 */
public class Session {

    private final String id;
    private final String accountId;
    private final long accountTokenVersion;
    private final Instant createdAt;
    private final Instant expiresAt;
    private volatile SessionStatus status;
    private volatile RevocationReason revocationReason;

    public Session(String id, String accountId, long accountTokenVersion,
                   Instant createdAt, Instant expiresAt) {
        this.id = id;
        this.accountId = accountId;
        this.accountTokenVersion = accountTokenVersion;
        this.createdAt = createdAt;
        this.expiresAt = expiresAt;
        this.status = SessionStatus.ACTIVE;
    }

    public String id() { return id; }
    public String accountId() { return accountId; }
    public long accountTokenVersion() { return accountTokenVersion; }
    public Instant createdAt() { return createdAt; }
    public Instant expiresAt() { return expiresAt; }
    public SessionStatus status() { return status; }
    public RevocationReason revocationReason() { return revocationReason; }

    public void revoke(RevocationReason reason) {
        this.status = SessionStatus.REVOKED;
        this.revocationReason = reason;
    }

    public void markExpired() {
        this.status = SessionStatus.EXPIRED;
    }
}
