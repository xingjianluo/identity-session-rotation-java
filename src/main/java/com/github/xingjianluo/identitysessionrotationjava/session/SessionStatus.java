package com.github.xingjianluo.identitysessionrotationjava.session;

/**
 * Lifecycle status of a session.
 */
public enum SessionStatus {
    ACTIVE,
    EXPIRED,   // lifetime elapsed without use
    REVOKED    // explicitly invalidated; reason kept on the session
}
