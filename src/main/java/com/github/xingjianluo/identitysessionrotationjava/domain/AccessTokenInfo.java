package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/** 访问令牌的服务端记录（只存哈希），绑定到会话链。 */
public class AccessTokenInfo {

    private final String tokenHash;
    private final String jti;
    private final String familyId;
    private final String sessionId;
    private final String username;
    private final Instant issuedAt;
    private final Instant expiresAt;
    private volatile boolean revoked;

    public AccessTokenInfo(String tokenHash, String jti, String familyId, String sessionId,
                           String username, Instant issuedAt, Instant expiresAt) {
        this.tokenHash = tokenHash;
        this.jti = jti;
        this.familyId = familyId;
        this.sessionId = sessionId;
        this.username = username;
        this.issuedAt = issuedAt;
        this.expiresAt = expiresAt;
    }

    public String getTokenHash() { return tokenHash; }
    public String getJti() { return jti; }
    public String getFamilyId() { return familyId; }
    public String getSessionId() { return sessionId; }
    public String getUsername() { return username; }
    public Instant getIssuedAt() { return issuedAt; }
    public Instant getExpiresAt() { return expiresAt; }
    public boolean isRevoked() { return revoked; }
    public void markRevoked() {
        this.revoked = true;
    }
}
