package com.github.xingjianluo.identitysessionrotationjava.domain;

/** 审计事件类型常量。 */
public final class AuditEventType {
    public static final String LOGIN_SUCCESS = "LOGIN_SUCCESS";
    public static final String LOGIN_FAILURE = "LOGIN_FAILURE";
    public static final String REFRESH_SUCCESS = "REFRESH_SUCCESS";
    public static final String REFRESH_FAILURE = "REFRESH_FAILURE";
    public static final String LOGOUT = "LOGOUT";
    public static final String PASSWORD_CHANGED = "PASSWORD_CHANGED";
    public static final String SESSION_REVOKED = "SESSION_REVOKED";
    public static final String ACCESS_DENIED = "ACCESS_DENIED";
    public static final String ACCOUNT_DISABLED = "ACCOUNT_DISABLED";
    public static final String ACCOUNT_ENABLED = "ACCOUNT_ENABLED";
    public static final String SESSION_LISTED = "SESSION_LISTED";
    public static final String SESSION_REVOKE_ONE = "SESSION_REVOKE_ONE";
    public static final String SESSION_REVOKE_OTHERS = "SESSION_REVOKE_OTHERS";
    public static final String SESSION_EVICTED = "SESSION_EVICTED";

    private AuditEventType() {}
}
