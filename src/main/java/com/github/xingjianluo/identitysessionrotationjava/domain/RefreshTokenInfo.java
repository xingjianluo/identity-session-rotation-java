package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/** 刷新令牌的服务端记录（只存哈希）。 */
public class RefreshTokenInfo {

    private final String tokenHash;
    private final String familyId;
    private final String sessionId;
    private final String username;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile Instant consumedAt;
    private volatile boolean revoked;

    public RefreshTokenInfo(String tokenHash, String familyId, String sessionId,
                            String username, Instant issuedAt, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.familyId = familyId;
        this.sessionId = sessionId;
        this.username = username;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getTokenHash() { return tokenHash; }
    public String getFamilyId() { return familyId; }
    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public Instant getConsumedAt() { return consumedAt; }
    public boolean isRevoked() { return revoked; }

    /** 标记令牌已被正常轮换消费（单次使用）。 */
    public void markConsumed(Instant at) {
        this.consumedAt = at;
    }

    /** 标记令牌因链路撤销而失效（区别于正常消费）。 */
    public void markRevoked() {
        this.revoked = true;
    }

    public boolean isConsumed() {
        return consumedAt != null;
    }
}
