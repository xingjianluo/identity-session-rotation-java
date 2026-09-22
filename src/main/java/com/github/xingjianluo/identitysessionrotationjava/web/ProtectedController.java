package com.github.xingjianluo.identitysessionrotationjava.web;

import jakarta.servlet.http.HttpServletRequest;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/** 受保护资源：用于演示不同权限范围的授权判定。 */
@RestController
@RequestMapping("/api")
public class ProtectedController {

    /** 需要 PROFILE_READ。 */
    @GetMapping("/profile")
    public Map<String, Object> profile(HttpServletRequest request) {
        return Map.of(
                "username", request.getAttribute("username"),
                "familyId", request.getAttribute("familyId"),
                "sessionId", request.getAttribute("sessionId"),
                "at", Instant.now().toString());
    }

    /** 需要 ORDER_READ。 */
    @GetMapping("/orders")
    public Map<String, Object> orders(HttpServletRequest request) {
        return Map.of(
                "username", request.getAttribute("username"),
                "orders", List.of("ORD-1001", "ORD-1002"));
    }
}
