package com.github.xingjianluo.identitysessionrotationjava.security;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import org.springframework.stereotype.Component;

/**
 * 令牌原文的 SHA-256 哈希。
 *
 * <p>令牌以原文形式只返回给客户端一次；服务端所有存储与查询均使用哈希，
 * 降低内存/导出泄露后的影响。
 */
@Component
public class TokenHasher {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    public String hash(String token) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(token.getBytes(StandardCharsets.UTF_8));
            char[] out = new char[digest.length * 2];
            for (int i = 0; i < digest.length; i++) {
                out[i * 2] = HEX[(digest[i] >> 4) & 0x0F];
                out[i * 2 + 1] = HEX[digest[i] & 0x0F];
            }
            return new String(out);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 不可用", e);
        }
    }
}
