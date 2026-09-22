package com.github.xingjianluo.identitysessionrotationjava.web.dto;

/** 修改密码请求。 */
public record ChangePasswordRequest(String oldPassword, String newPassword) {
}
