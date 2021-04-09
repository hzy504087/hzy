package com.leaf.config;

//import com.leaf.filter.JwtAuthenticationFilter;
//import com.leaf.filter.JwtLoginFilter;
//import com.leaf.service.LoginCountService;
//import com.leaf.service.VerifyCodeService;
import com.leaf.filter.JwtAuthenticationFilter;
import com.leaf.filter.JwtLoginFilter;
import com.leaf.service.VerifyCodeService;
import com.leaf.service.login.LoginCountService;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import java.util.ArrayList;
import java.util.List;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {
    public static String ADMIN = "ROLE_ADMIN";

    public static String USER = "ROLE_USER";
//
    private final VerifyCodeService verifyCodeService;

    private final LoginCountService loginCountService;

    /**
     * 开放访问的请求
     */
    private final static String[] PERMIT_ALL_MAPPING = {
            "/api/hello",
            "/api/login",
            "/api/home",
            "/api/verifyImage",
            "/api/image/verify",
            "/images/**"
    };

    public WebSecurityConfig(VerifyCodeService verifyCodeService, LoginCountService loginCountService) {
        this.verifyCodeService = verifyCodeService;
        this.loginCountService = loginCountService;
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 跨域配置
     */
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        // 允许跨域访问的 URL
        List<String> allowedOriginsUrl = new ArrayList<>();
        allowedOriginsUrl.add("http://localhost:8080");
//        allowedOriginsUrl.add("http://127.0.0.1:8080");

        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true);
        // 设置允许跨域访问的 URL
        config.setAllowedOrigins(allowedOriginsUrl);
        config.addAllowedHeader("*");
        config.addAllowedMethod("*");
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", config);
        return source;
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(PERMIT_ALL_MAPPING)
                .permitAll()
                .antMatchers("/sys/user/**", "/sys/data", "/sys/logout")
                // USER 和 ADMIN 都可以访问
                .hasAnyAuthority(USER, ADMIN)
                .antMatchers("/**")
                // 只有 ADMIN 才可以访问
                .hasAnyAuthority(ADMIN)
                .anyRequest()
                .authenticated()
                .and()
                // 添加过滤器链,前一个参数过滤器， 后一个参数过滤器添加的地方
                // 登陆过滤器
                .addFilterBefore(new JwtLoginFilter("/api/login", authenticationManager(), verifyCodeService, loginCountService), UsernamePasswordAuthenticationFilter.class)
                // 请求过滤器
                .addFilterBefore(new JwtAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class)
                // 开启跨域
                .cors()
                .and()
                // 开启 csrf
                .csrf()
                // .disable();
                .ignoringAntMatchers(PERMIT_ALL_MAPPING)
                .csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse())
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    @Override
    public void configure(WebSecurity web) throws Exception {
        super.configure(web);
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        // 在内存中写入用户数据
             auth
                  .authenticationProvider(daoAuthenticationProvider());
//                .inMemoryAuthentication()
//                .withUser("user")
//                .password(passwordEncoder().encode("123456"))
//                .authorities("ROLE_USER")
//                .and()
//                .withUser("admin")
//                .password(passwordEncoder().encode("123456"))
//                .authorities("ROLE_ADMIN")
//                .and()
//                .withUser("block")
//                .password(passwordEncoder().encode("123456"))
//                .authorities("ROLE_USER")
//                .accountLocked(true);
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider() {

        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setHideUserNotFoundExceptions(false);
        provider.setPasswordEncoder(passwordEncoder());
        provider.setUserDetailsService(new AccountDetailsService());
        return provider;
    }
}