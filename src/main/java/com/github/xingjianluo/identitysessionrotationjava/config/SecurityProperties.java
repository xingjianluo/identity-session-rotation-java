package com.github.xingjianluo.identitysessionrotationjava.config;

import java.util.ArrayList;
import java.util.List;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** 安全相关可配置项（骨架）。 */
@ConfigurationProperties(prefix = "app.security")
public class SecurityProperties {

    /** 访问令牌有效期（秒）。 */
    private long accessTokenTtlSeconds = 300;

    /** 刷新令牌有效期（秒）。 */
    private long refreshTokenTtlSeconds = 1209600;

    /** 每个账户允许同时保持的活跃登录（设备会话）数上限。 */
    private int maxConcurrentSessions = 5;

    /** 令牌签发者标识。 */
    private String issuer = "local-identity";

    /** 启动时初始化的演示账户。 */
    private List<BootstrapAccount> bootstrapAccounts = new ArrayList<>();

    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long v) { this.accessTokenTtlSeconds = v; }

    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long v) { this.refreshTokenTtlSeconds = v; }

    public int getMaxConcurrentSessions() { return maxConcurrentSessions; }
    public void setMaxConcurrentSessions(int v) { this.maxConcurrentSessions = v; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public List<BootstrapAccount> getBootstrapAccounts() { return bootstrapAccounts; }
    public void setBootstrapAccounts(List<BootstrapAccount> v) { this.bootstrapAccounts = v; }

    /** 演示账户配置项：app.security.bootstrap-accounts[i]。 */
    public static class BootstrapAccount {
        private String username;
        private String password;
        private List<String> roles = new ArrayList<>();

        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }

        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }

        public List<String> getRoles() { return roles; }
        public void setRoles(List<String> roles) { this.roles = roles; }
    }
}
