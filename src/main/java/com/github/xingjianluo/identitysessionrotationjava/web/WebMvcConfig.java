package com.github.xingjianluo.identitysessionrotationjava.web;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

/** 为受保护路由注册授权拦截器（具体所需权限由 {@link ProtectedRoutes} 解析）。 */
@Configuration
public class WebMvcConfig implements WebMvcConfigurer {

    private final AuthorizationInterceptor authorizationInterceptor;

    public WebMvcConfig(AuthorizationInterceptor authorizationInterceptor) {
        this.authorizationInterceptor = authorizationInterceptor;
    }

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(authorizationInterceptor)
                .addPathPatterns(
                        "/api/auth/logout",
                        "/api/account/password",
                        "/api/sessions",
                        "/api/sessions/**",
                        "/api/profile",
                        "/api/orders",
                        "/api/admin/**")
                .order(0);
    }
}
