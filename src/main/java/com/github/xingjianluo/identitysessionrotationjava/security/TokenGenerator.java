package com.github.xingjianluo.identitysessionrotationjava.security;

import java.security.SecureRandom;
import java.util.Base64;
import org.springframework.stereotype.Component;

/**
 * 使用 {@link SecureRandom} 生成不透明令牌与内部标识。
 *
 * <p>令牌带前缀便于客户端/日志区分类型，正文为 URL-safe Base64 随机串：
 * <ul>
 *   <li>访问令牌：{@code vat_} + 32 字节随机数</li>
 *   <li>刷新令牌：{@code vrt_} + 32 字节随机数</li>
 *   <li>内部 ID：{@code vid_} + 16 字节随机数</li>
 * </ul>
 */
@Component
public class TokenGenerator {

    public static final String ACCESS_PREFIX = "vat_";
    public static final String REFRESH_PREFIX = "vrt_";

    private final SecureRandom random = new SecureRandom();

    public String newAccessToken() {
        return ACCESS_PREFIX + randomUrlSafe(32);
    }

    public String newRefreshToken() {
        return REFRESH_PREFIX + randomUrlSafe(32);
    }

    public String newId() {
        return "vid_" + randomUrlSafe(16);
    }

    private String randomUrlSafe(int bytes) {
        byte[] buf = new byte[bytes];
        random.nextBytes(buf);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(buf);
    }
}
