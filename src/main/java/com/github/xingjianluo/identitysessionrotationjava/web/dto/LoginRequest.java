package com.github.xingjianluo.identitysessionrotationjava.web.dto;

/**
 * 登录请求。{@code clientId} 可选：客户端/来源标识（如 mobile、browser、cli），
 * 用于多设备会话列表区分来源。
 */
public record LoginRequest(String username, String password, String clientId) {

    /** 兼容不带 clientId 的调用。 */
    public LoginRequest(String username, String password) {
        this(username, password, null);
    }
}
