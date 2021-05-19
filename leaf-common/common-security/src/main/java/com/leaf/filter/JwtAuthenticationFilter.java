package com.leaf.filter;

import cn.hutool.core.util.StrUtil;
import com.leaf.entity.AccountDetails;
import com.leaf.utils.JwtTokenUtil;
import io.jsonwebtoken.JwtException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    @Autowired
    private JwtTokenUtil jwtUtils;

    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {

        String token=httpServletRequest.getHeader(jwtUtils.getHeader());
        if(StrUtil.isBlankOrUndefined(token)){
            filterChain.doFilter(httpServletRequest, httpServletResponse);
            return;
        }
        Boolean tokenExpired = jwtUtils.isTokenExpired(token);
        if (tokenExpired) {
            throw new JwtException("token已过期");
        }
        UsernamePasswordAuthenticationToken authentication
                = new UsernamePasswordAuthenticationToken(token, null,new AccountDetails().getAuthorities());

        SecurityContextHolder.getContext().setAuthentication(authentication);
        filterChain.doFilter(httpServletRequest, httpServletResponse);
    }
//     if (!request.getRequestURI().equals("/admin/login.json") && !request.getRequestURI().equals("/admin/logout.json")) {
//        StringRedisTemplate stringRedisTemplate = stringRedisTemplateEx.getUserDateBase();
//        String token = request.getHeader("token");
//        if (!StringUtils.isEmpty(token)) {
//            String key = RedisKey.userToken + token;
//            Boolean isLogin = stringRedisTemplate.hasKey(key);
//            if (isLogin != null && isLogin) {
//                String s = stringRedisTemplate.opsForValue().get(key);
//                AdminUser adminUser = JSONObject.parseObject(s, AdminUser.class);
//                assert adminUser != null;
//                // 用户的权限
//                Collection<? extends GrantedAuthority> authorities = adminUser.getAuthorities();
//                UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(adminUser, null, authorities);
//                SecurityContextHolder.getContext()
//                        .setAuthentication(authentication);
//                request.setAttribute("userId", adminUser.getUserId());
//            } else {
////                    notToken(response);
////                    return;
//            }
//        } else {
////                notToken(response);
////                return;
//        }
//    }
//        filterChain.doFilter(request, response);
}
