package com.github.xingjianluo.identitysessionrotationjava.error;

/**
 * Stable, externally visible error taxonomy. Each code maps to one HTTP
 * status; codes are part of the API contract and must not be renamed.
 */
public enum ErrorCode {
    INVALID_CREDENTIALS(401),        // login failure; never reveals account existence
    TOKEN_INVALID(401),              // malformed / unknown access token
    TOKEN_EXPIRED(401),              // access token past its lifetime
    SESSION_REVOKED(401),            // session explicitly revoked (reason attached)
    ACCOUNT_STATE_INVALID(401),      // account disabled after token issuance
    REFRESH_TOKEN_INVALID(401),      // unknown or malformed refresh token
    REFRESH_TOKEN_EXPIRED(401),      // refresh token past its lifetime
    REFRESH_TOKEN_REUSED(401),       // consumed refresh token presented after the race grace window
    REFRESH_TOKEN_RACE(409),         // lost a concurrent rotation of the same token; chain kept
    PERMISSION_DENIED(403);          // authenticated but lacks role/permission

    private final int httpStatus;

    ErrorCode(int httpStatus) {
        this.httpStatus = httpStatus;
    }

    public int httpStatus() {
        return httpStatus;
    }
}
