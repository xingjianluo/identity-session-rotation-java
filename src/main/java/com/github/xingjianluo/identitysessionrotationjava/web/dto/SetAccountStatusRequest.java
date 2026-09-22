package com.github.xingjianluo.identitysessionrotationjava.web.dto;

/** 管理员启停账户请求。 */
public record SetAccountStatusRequest(String username, boolean active) {
}
