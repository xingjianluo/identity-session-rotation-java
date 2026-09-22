package com.github.xingjianluo.identitysessionrotationjava.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Tunables for token lifetimes. All values are configurable via
 * {@code security.*} properties.
 */
@Component
@ConfigurationProperties(prefix = "security")
public class SecurityProperties {

    /** Access token lifetime in seconds. */
    private long accessTokenTtlSeconds = 300;

    /** Refresh token (and session) lifetime in seconds. */
    private long refreshTokenTtlSeconds = 3600;

    /**
     * Grace window after a refresh token is consumed during which another
     * presentation of it is treated as a lost concurrent rotation
     * (REFRESH_TOKEN_RACE, chain kept) instead of theft/replay
     * (REFRESH_TOKEN_REUSED, chain revoked).
     */
    private long refreshReuseGraceSeconds = 5;

    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long v) { this.accessTokenTtlSeconds = v; }
    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long v) { this.refreshTokenTtlSeconds = v; }
    public long getRefreshReuseGraceSeconds() { return refreshReuseGraceSeconds; }
    public void setRefreshReuseGraceSeconds(long v) { this.refreshReuseGraceSeconds = v; }
}
