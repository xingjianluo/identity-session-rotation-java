package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.time.Instant;

/**
 * 一次“设备登录”的元数据：以会话链 familyId 为键。
 * 同一设备后续的刷新轮换仍属于同一条 DeviceSession。
 */
public class DeviceSession {

    private final String familyId;
    private final String username;
    private final String clientId;
    private final String clientName;
    private final String userAgent;
    private final String ip;
    private final Instant loginAt;
    private volatile Instant lastActiveAt;

    public DeviceSession(String familyId, String username, String clientId, String clientName,
                         String userAgent, String ip, Instant loginAt) {
        this.familyId = familyId;
        this.username = username;
        this.clientId = clientId;
        this.clientName = clientName;
        this.userAgent = userAgent;
        this.ip = ip;
        this.loginAt = loginAt;
        this.lastActiveAt = loginAt;
    }

    public String getFamilyId() { return familyId; }
    public String getUsername() { return username; }
    public String getClientId() { return clientId; }
    public String getClientName() { return clientName; }
    public String getUserAgent() { return userAgent; }
    public String getIp() { return ip; }
    public Instant getLoginAt() { return loginAt; }
    public Instant getLastActiveAt() { return lastActiveAt; }

    /** 更新最近活跃时间：仅在更晚时推进（避免乱序请求把时间拉回去）。 */
    public void touch(Instant at) {
        if (at != null && (lastActiveAt == null || at.isAfter(lastActiveAt))) {
            this.lastActiveAt = at;
        }
    }
}
