package com.github.xingjianluo.identitysessionrotationjava.security;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.util.Base64;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import org.springframework.stereotype.Component;

/**
 * 基于 PBKDF2WithHmacSHA256 的口令哈希。
 *
 * <p>存储格式：{@code pbkdf2$<iterations>$<saltBase64>$<hashBase64>}。
 * 使用恒定时间比较，避免时序侧信道。
 */
@Component
public class PasswordEncoder {

    private static final String ALGORITHM = "PBKDF2WithHmacSHA256";
    private static final int ITERATIONS = 120_000;
    private static final int SALT_LENGTH = 16;
    private static final int KEY_LENGTH = 256;
    private static final String PREFIX = "pbkdf2$";

    private final SecureRandom random = new SecureRandom();

    public String encode(String rawPassword) {
        byte[] salt = new byte[SALT_LENGTH];
        random.nextBytes(salt);
        byte[] hash = pbkdf2(rawPassword.toCharArray(), salt, ITERATIONS);
        return PREFIX + ITERATIONS + "$"
                + Base64.getEncoder().encodeToString(salt) + "$"
                + Base64.getEncoder().encodeToString(hash);
    }

    public boolean matches(String rawPassword, String encoded) {
        if (encoded == null || !encoded.startsWith(PREFIX)) {
            return false;
        }
        String[] parts = encoded.substring(PREFIX.length()).split("\\$");
        if (parts.length != 3) {
            return false;
        }
        int iterations;
        byte[] salt;
        byte[] expected;
        try {
            iterations = Integer.parseInt(parts[0]);
            salt = Base64.getDecoder().decode(parts[1]);
            expected = Base64.getDecoder().decode(parts[2]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        byte[] actual = pbkdf2(rawPassword.toCharArray(), salt, iterations);
        return MessageDigestEquals.isEqual(expected, actual);
    }

    private byte[] pbkdf2(char[] password, byte[] salt, int iterations) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LENGTH);
            SecretKeyFactory factory = SecretKeyFactory.getInstance(ALGORITHM);
            return factory.generateSecret(spec).getEncoded();
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new IllegalStateException("口令哈希不可用: " + ALGORITHM, e);
        }
    }

    /** 恒定时间字节比较（避免引入额外依赖）。 */
    private static final class MessageDigestEquals {
        static boolean isEqual(byte[] a, byte[] b) {
            return java.security.MessageDigest.isEqual(a, b);
        }
    }
}
