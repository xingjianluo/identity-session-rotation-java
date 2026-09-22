package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.util.Set;

/** 本地账户。 */
public class Account {

    private final String username;
    private volatile String passwordHash;
    private volatile AccountStatus status;
    private final Set<Role> roles;

    public Account(String username, String passwordHash, AccountStatus status, Set<Role> roles) {
        this.username = username;
        this.passwordHash = passwordHash;
        this.status = status;
        this.roles = roles;
    }

    public String getUsername() { return username; }
    public String getPasswordHash() { return passwordHash; }
    public void setPasswordHash(String passwordHash) { this.passwordHash = passwordHash; }
    public AccountStatus getStatus() { return status; }
    public void setStatus(AccountStatus status) { this.status = status; }
    public Set<Role> getRoles() { return roles; }
}
