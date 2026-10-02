package com.github.xingjianluo.identitysessionrotationjava.service;

/**
 * 登录时的客户端/来源上下文：用于设备会话列表区分“是哪个客户端”。
 *
 * @param clientId   客户端自报标识（如 mobile / browser / cli），可空
 * @param userAgent  请求 User-Agent 头，可空
 * @param ip        来源 IP，可空
 */
public record ClientContext(String clientId, String userAgent, String ip) {

    public static ClientContext of(String clientId, String userAgent, String ip) {
        return new ClientContext(blankToNull(clientId), blankToNull(userAgent), blankToNull(ip));
    }

    /** 无可识别来源时的兜底展示名。 */
    public String displayName() {
        if (clientId != null) {
            return clientId;
        }
        if (userAgent != null) {
            return userAgent.length() > 48 ? userAgent.substring(0, 48) + "…" : userAgent;
        }
        return "unknown";
    }

    private static String blankToNull(String s) {
        return (s == null || s.isBlank()) ? null : s.trim();
    }
}
