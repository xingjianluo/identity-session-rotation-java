package com.github.xingjianluo.identitysessionrotationjava.audit;

/**
 * Categories of security-relevant events persisted for later querying.
 */
public enum AuditEventType {
    LOGIN_SUCCESS,
    LOGIN_FAILURE,
    TOKEN_REFRESHED,
    REFRESH_FAILURE,
    REFRESH_TOKEN_REUSE_DETECTED,
    SESSION_REVOKED,
    LOGOUT,
    PASSWORD_CHANGED,
    ACCESS_DENIED
}
