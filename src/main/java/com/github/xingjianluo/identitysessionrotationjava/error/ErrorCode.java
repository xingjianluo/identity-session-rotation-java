package com.github.xingjianluo.identitysessionrotationjava.error;

/**
 * 对外稳定的错误分类：每种失效/拒绝原因都有独立的稳定 code 与 HTTP 状态。
 */
public enum ErrorCode {
    MISSING_TOKEN(401, "missing_token", "缺少访问令牌"),
    MALFORMED_AUTHORIZATION(401, "malformed_authorization", "Authorization 头格式错误"),
    INVALID_TOKEN(401, "invalid_token", "访问令牌无效"),
    TOKEN_EXPIRED(401, "token_expired", "访问令牌已过期"),
    TOKEN_REVOKED(401, "token_revoked", "访问令牌已被撤销"),
    SESSION_REVOKED_LOGOUT(401, "session_revoked_logout", "会话因主动登出已结束"),
    SESSION_REVOKED_PASSWORD_CHANGED(401, "session_revoked_password_changed", "会话因账户密码变更已失效"),
    SESSION_REVOKED_ACCOUNT_DISABLED(401, "session_revoked_account_disabled", "会话因账户被停用已失效"),
    SESSION_REVOKED_REFRESH_REUSE(401, "session_revoked_refresh_reuse", "会话因刷新令牌重放已被撤销"),
    SESSION_REVOKED_DEVICE_REVOKED(401, "session_revoked_device_revoked", "该设备会话已被单独撤销"),
    SESSION_REVOKED_OTHER_DEVICES_LOGOUT(401, "session_revoked_other_devices_logout", "该设备会话因“退出其他设备”已结束"),
    SESSION_REVOKED_MAX_SESSIONS(401, "session_revoked_max_sessions", "因登录设备数达到上限，该最久未活跃会话已被清理"),
    ACCOUNT_INACTIVE(401, "account_inactive", "账户已被停用"),
    INSUFFICIENT_PERMISSION(403, "insufficient_permission", "权限不足"),
    INVALID_CREDENTIALS(401, "invalid_credentials", "用户名或密码错误"),
    REFRESH_TOKEN_INVALID(401, "invalid_grant", "刷新令牌无效"),
    REFRESH_TOKEN_EXPIRED(401, "refresh_token_expired", "刷新令牌已过期"),
    REFRESH_TOKEN_REUSED(401, "refresh_token_reused", "刷新令牌已被使用，会话链已被撤销"),
    OLD_PASSWORD_INCORRECT(401, "old_password_incorrect", "原密码不正确"),
    ACCOUNT_NOT_FOUND(404, "account_not_found", "账户不存在"),
    SESSION_NOT_FOUND(404, "session_not_found", "会话不存在或不属于当前账户"),
    BAD_REQUEST(400, "bad_request", "请求参数不合法");

    private final int httpStatus;
    private final String code;
    private final String defaultMessage;

    ErrorCode(int httpStatus, String code, String defaultMessage) {
        this.httpStatus = httpStatus;
        this.code = code;
        this.defaultMessage = defaultMessage;
    }

    public int httpStatus() { return httpStatus; }
    public String code() { return code; }
    public String defaultMessage() { return defaultMessage; }
}
