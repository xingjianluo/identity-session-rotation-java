package com.github.xingjianluo.identitysessionrotationjava.token;

/**
 * What a successful login or refresh returns to the client.
 */
public record TokenPair(String accessToken, String refreshToken, long accessTokenExpiresInSeconds) {
}
