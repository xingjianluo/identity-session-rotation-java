package com.github.xingjianluo.identitysessionrotationjava.web;

/**
 * Extracts the token from an {@code Authorization: Bearer <token>} header.
 */
public final class BearerToken {

    private BearerToken() {
    }

    public static String extract(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        String header = authorizationHeader.trim();
        if (!header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            return null;
        }
        String token = header.substring(7).trim();
        return token.isEmpty() ? null : token;
    }
}
