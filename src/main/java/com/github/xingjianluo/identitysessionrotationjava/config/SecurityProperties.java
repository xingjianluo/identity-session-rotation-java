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

    /** 令牌签发者标识。 */
    private String issuer = "local-identity";

    /**
     * 每个账号允许同时保持的活跃登录（设备会话）数上限，超出后按最久未活动淘汰。
     *
     * <p>触发淘汰的那次新登录豁免：它不会被自己触发的淘汰清掉，被清掉的只能是
     * 此前已存在的登录。配置为 {@code <=0} 时有效上限按 1 解释（每次至少保留
     * 刚登录成功的那一个）。
     */
    private int maxActiveSessionsPerAccount = 5;

    /** 启动时初始化的演示账户。 */
    private List<BootstrapAccount> bootstrapAccounts = new ArrayList<>();

    public long getAccessTokenTtlSeconds() { return accessTokenTtlSeconds; }
    public void setAccessTokenTtlSeconds(long v) { this.accessTokenTtlSeconds = v; }

    public long getRefreshTokenTtlSeconds() { return refreshTokenTtlSeconds; }
    public void setRefreshTokenTtlSeconds(long v) { this.refreshTokenTtlSeconds = v; }

    public String getIssuer() { return issuer; }
    public void setIssuer(String issuer) { this.issuer = issuer; }

    public int getMaxActiveSessionsPerAccount() { return maxActiveSessionsPerAccount; }
    public void setMaxActiveSessionsPerAccount(int v) { this.maxActiveSessionsPerAccount = v; }

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
