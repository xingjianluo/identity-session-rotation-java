package com.github.xingjianluo.identitysessionrotationjava.domain;

/** 会话/令牌链被撤销的原因，用于区分失效类型。 */
public enum RevocationReason {
    LOGOUT,
    PASSWORD_CHANGED,
    ACCOUNT_DISABLED,
    REFRESH_REUSE,
    /** 用户单独撤销了某个设备会话。 */
    DEVICE_REVOKED,
    /** 用户“退出其他所有设备”。 */
    OTHER_DEVICES_LOGOUT,
    /** 超过每账户活跃登录上限，按最久未活跃被清理。 */
    MAX_SESSIONS_EVICTED
}
