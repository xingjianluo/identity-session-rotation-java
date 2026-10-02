package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/**
 * 一次设备登录（多设备会话模型中的“一个登录”）。
 *
 * <p>以 familyId 为稳定标识：同一次登录内的刷新轮换会更换内部 Session，
 * 但 familyId 不变，因此用户看到的“登录”跨刷新保持稳定。
 */
public class DeviceSession {

    private final String familyId;
    private final String username;
    private final String client;
    private final Instant createdAt;
    private volatile Instant lastActiveAt;
    private volatile boolean active;

    public DeviceSession(String familyId, String username, String client,
                         Instant createdAt) {
        this.familyId = familyId;
        this.username = username;
        this.client = client;
        this.createdAt = createdAt;
        this.lastActiveAt = createdAt;
        this.active = true;
    }

    public String getFamilyId() { return familyId; }
    public String getUsername() { return username; }
    public String getClient() { return client; }
    public Instant getCreatedAt() { return createdAt; }
    public Instant getLastActiveAt() { return lastActiveAt; }
    public boolean isActive() { return active; }

    public void touch(Instant at) {
        this.lastActiveAt = at;
    }

    public void markInactive() {
        this.active = false;
    }
}
