package com.github.xingjianluo.identitysessionrotationjava.domain;

import java.util.EnumSet;
import java.util.Set;

/**
 * 角色及其被授予的权限集合。
 *
 * <ul>
 *   <li>USER：读取自己的资料、读取/写入订单</li>
 *   <li>ADMIN：拥有全部权限（含审计查询、账户管理）</li>
 * </ul>
 */
public enum Role {
    USER(EnumSet.of(
            Permission.PROFILE_READ,
            Permission.ORDER_READ,
            Permission.ORDER_WRITE
    )),
    ADMIN(EnumSet.allOf(Permission.class));

    private final Set<Permission> permissions;

    Role(Set<Permission> permissions) {
        this.permissions = permissions;
    }

    public Set<Permission> permissions() {
        return permissions;
    }
}
