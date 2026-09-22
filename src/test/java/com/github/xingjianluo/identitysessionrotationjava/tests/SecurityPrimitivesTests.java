package com.github.xingjianluo.identitysessionrotationjava.tests;

import com.github.xingjianluo.identitysessionrotationjava.security.PasswordEncoder;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenGenerator;
import com.github.xingjianluo.identitysessionrotationjava.security.TokenHasher;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import static org.assertj.core.api.Assertions.assertThat;

/** 口令哈希与令牌生成/哈希基础能力。 */
class SecurityPrimitivesTests {

    private static final Logger log = LoggerFactory.getLogger(SecurityPrimitivesTests.class);

    private final PasswordEncoder passwordEncoder = new PasswordEncoder();
    private final TokenGenerator tokenGenerator = new TokenGenerator();
    private final TokenHasher tokenHasher = new TokenHasher();

    @Test
    void passwordHashIsSaltedAndVerifies() {
        String raw = "S3cret-passw0rd!";
        String h1 = passwordEncoder.encode(raw);
        String h2 = passwordEncoder.encode(raw);

        log.info("[输入] 同一口令两次哈希 => {} / {}", h1, h2);
        assertThat(h1).startsWith("pbkdf2$").isNotEqualTo(h2);
        assertThat(passwordEncoder.matches(raw, h1)).isTrue();
        assertThat(passwordEncoder.matches(raw, h2)).isTrue();
        assertThat(passwordEncoder.matches("wrong", h1)).isFalse();
        assertThat(passwordEncoder.matches(raw, "not-a-valid-hash")).isFalse();
        log.info("[判定依据] 加盐哈希可验证、两次哈希不同、错误口令被拒绝");
    }

    @Test
    void tokensAreUniqueAndHashesDeterministic() {
        String a1 = tokenGenerator.newAccessToken();
        String a2 = tokenGenerator.newAccessToken();
        String r1 = tokenGenerator.newRefreshToken();
        log.info("[输入] access1={} access2={} refresh1={}", a1, a2, r1);

        assertThat(a1).startsWith("vat_").isNotEqualTo(a2);
        assertThat(r1).startsWith("vrt_");
        assertThat(tokenHasher.hash(a1))
                .isEqualTo(tokenHasher.hash(a1))
                .isNotEqualTo(tokenHasher.hash(a2));
        assertThat(tokenHasher.hash(a1)).hasSize(64);
        log.info("[判定依据] 令牌唯一、SHA-256 哈希确定且为 64 位十六进制");
    }
}
