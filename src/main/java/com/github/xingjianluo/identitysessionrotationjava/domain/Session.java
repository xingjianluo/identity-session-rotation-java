package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/**
 * 一次登录会话。刷新轮换时会创建新的 Session，但共享同一个 familyId（会话链）。
 */
public class Session {

    private final String id;
    private final String familyId;
    private final String username;
    private final Instant createdAt;
    private volatile boolean revoked;
    private volatile RevocationReason revocationReason;

    public Session(String id, String familyId, String username, Instant createdAt) {
        this.id = id;
        this.familyId = familyId;
        this.username = username;
        this.createdAt = createdAt;
        this.revoked = false;
    }

    public String getId() { return id; }
    public String getFamilyId() { return familyId; }
    public String getUsername() { return username; }
    public Instant getCreatedAt() { return createdAt; }
    public boolean isRevoked() { return revoked; }
    public RevocationReason getRevocationReason() { return revocationReason; }
    /**
     * 标记会话被撤销。撤销是终态：已撤销的会话不会因重复撤销而改变原因，
     * 第一次记录的原因即为对外可解释的失效原因。
     */
    public void markRevoked(RevocationReason reason) {
        if (!this.revoked) {
            this.revoked = true;
            this.revocationReason = reason;
        }
    }
}
