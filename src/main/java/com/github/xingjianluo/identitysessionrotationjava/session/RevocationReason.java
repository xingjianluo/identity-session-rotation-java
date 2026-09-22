package com.github.xingjianluo.identitysessionrotationjava.session;

/**
 * Why a session (and its token chain) was revoked. Kept so that revocation
 * stays distinguishable from ordinary expiry.
 */
public enum RevocationReason {
    LOGOUT,
    PASSWORD_CHANGED,
    REFRESH_TOKEN_REUSE_DETECTED,
    ACCOUNT_DISABLED
}
