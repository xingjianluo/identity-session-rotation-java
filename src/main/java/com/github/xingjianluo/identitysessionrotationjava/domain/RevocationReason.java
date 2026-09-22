package com.github.xingjianluo.identitysessionrotationjava.domain;

/** 会话/令牌链被撤销的原因，用于区分失效类型。 */
public enum RevocationReason {
    LOGOUT,
    PASSWORD_CHANGED,
    ACCOUNT_DISABLED,
    REFRESH_REUSE
}
