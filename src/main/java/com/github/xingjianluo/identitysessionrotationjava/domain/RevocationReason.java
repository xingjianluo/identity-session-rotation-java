package com.github.xingjianluo.identitysessionrotationjava.domain;

/** 会话/令牌链被撤销的原因，用于区分失效类型。 */
public enum RevocationReason {
    LOGOUT,
    PASSWORD_CHANGED,
    ACCOUNT_DISABLED,
    REFRESH_REUSE,
    /** 用户在设备列表中主动撤销某个登录（含“退出其他所有设备”）。 */
    DEVICE_REVOKED,
    /** 超出账号同时在线会话数上限，按最久未活动规则被清理。 */
    SESSION_LIMIT_EVICTED
}
