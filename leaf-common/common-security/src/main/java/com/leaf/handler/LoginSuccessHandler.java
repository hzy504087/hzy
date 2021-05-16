package com.leaf.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.leaf.entity.AccountDetailsService;
import com.leaf.utils.JwtTokenUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Collection;

@Component
public class LoginSuccessHandler implements AuthenticationSuccessHandler {

    @Autowired
    private JwtTokenUtil jwtTokenUtil;



    @Autowired
    private AccountDetailsService accountDetailsService;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // 获取用户登陆角色
        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();
        // 遍历用户角色
        StringBuffer stringBuffer = new StringBuffer();
        authorities.forEach(authority -> {
            stringBuffer.append(authority.getAuthority()).append(",");
        });
        Object details = authentication.getDetails();
//        if (details.getRememberMe() != null && details.getRememberMe()) {
////            expirationTime = COOKIE_EXPIRATION_TIME * 1000;
////            cookExpirationTime = COOKIE_EXPIRATION_TIME;
//        }
        String name = authentication.getName();
        jwtTokenUtil.generateToken(name,null);
        response.setContentType("application/json; charset=UTF-8");
        PrintWriter out = response.getWriter();
        Result result1 = Result.success("");
        out.write(new ObjectMapper().writeValueAsString(result1));
        out.flush();
        out.close();

//        response.setContentType("application/json;charset=UTF-8");
//		ServletOutputStream outputStream = response.getOutputStream();
//		System.out.println(request);
//		System.out.println(response);
//		System.out.println(authentication);
//		UserDetails userDetails=accountDetailsService.loadUserByUsername("user");
//		// 生成jwt，并放置到请求头中
//		String token = jwtTokenUtil.generateToken(userDetails,null);
//
//		response.setHeader("Authorization",token);
//
//		Result result = Result.success("");
//
//		outputStream.write(JSONUtil.toJsonStr(result).getBytes("UTF-8"));
//
//		outputStream.flush();
//		outputStream.close();
    }

}
