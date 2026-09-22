package com.github.xingjianluo.identitysessionrotationjava.account;

import java.util.Set;

/**
 * A local account. {@code tokenVersion} is bumped on password change so that
 * sessions issued before the change can be invalidated deterministically.
 */
public class Account {

    private final String id;
    private final String username;
    private String passwordHash;
    private final Set<String> roles;
    private final Set<String> permissions;
    private volatile AccountStatus status;
    private volatile long tokenVersion;

    public Account(String id, String username, String passwordHash,
                   Set<String> roles, Set<String> permissions) {
        this.id = id;
        this.username = username;
        this.passwordHash = passwordHash;
        this.roles = Set.copyOf(roles);
        this.permissions = Set.copyOf(permissions);
        this.status = AccountStatus.ACTIVE;
        this.tokenVersion = 0L;
    }

    public String id() { return id; }
    public String username() { return username; }
    public String passwordHash() { return passwordHash; }
    public Set<String> roles() { return roles; }
    public Set<String> permissions() { return permissions; }
    public AccountStatus status() { return status; }
    public long tokenVersion() { return tokenVersion; }

    public void changePassword(String newPasswordHash) {
        this.passwordHash = newPasswordHash;
        this.tokenVersion++;
    }

    public void disable() { this.status = AccountStatus.DISABLED; }
}
