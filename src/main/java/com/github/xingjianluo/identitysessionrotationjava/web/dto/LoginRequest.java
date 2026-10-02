package com.github.xingjianluo.identitysessionrotationjava.web.dto;

/**
 * 登录请求。client 为可选的客户端/来源标识（如 mobile / web / cli），
 * 用于多设备会话列表中区分登录来源；缺省记为 unknown。
 */
public record LoginRequest(String username, String password, String client) {

    /** 兼容旧的两参数调用（不携带客户端标识）。 */
    public LoginRequest(String username, String password) {
        this(username, password, null);
    }
}
