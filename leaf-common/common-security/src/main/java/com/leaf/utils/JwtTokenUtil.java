package com.leaf.utils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.Data;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @Auther: night
 * @Desc: jwt工具类
 */
@Component
@Data
public class JwtTokenUtil {
    // 令牌自定义标识
    @Value("${night.jwt.header}")
    private String Header;
    //JWT密钥
    @Value("${night.jwt.secret}")
    private String secret;
    //JWT有效时间
    @Value("${night.jwt.expireDate}")
    private Long expireDate;
//    @Autowired
//    private RedisCache redisCache;
    /**
     * 生成token令牌
     * @param userDetails 用户
     * @return 令牌
     */
    public String createToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", userDetails.getUsername());
        claims.put("created", new Date());
        return createToken(claims);
    }
    /**
     * 生成token令牌
     *
     * @param username 用户
     * @return 令牌
     */
    public String createToken(String username) {

        Map<String, Object> claims = new HashMap<>();
        claims.put("sub", username);
        claims.put("created", new Date());
        return createToken(claims);
    }

    /**
     * 从令牌中获取用户名
     * @param token 令牌
     * @return 用户名
     */
    public String getUsernameFromToken(String token)
    {
        Claims claims = parseToken(token);
        return claims.getSubject();
    }
    /**
     * 刷新令牌
     *
     * @param token 原令牌
     * @return 新令牌
     */
    public String refreshToken(String token) {
        Claims claims = parseToken(token);
        claims.put("created", new Date());
        String refreshedToken = createToken(claims);
        return refreshedToken;
    }
    /**
     * 判断令牌是否过期
     *
     * @param token 令牌
     * @return 是否过期
     */
    public Boolean isTokenExpired(String token) {
            Claims claims = parseToken(token);
            Date expiration = claims.getExpiration();
            return expiration.before(new Date());
    }
    /**
     * 从数据声明生成令牌
     *
     * @param claims 数据声明
     * @return 令牌
     */
    private String createToken(Map<String, Object> claims)
    {
        Date expirationDate = new Date(System.currentTimeMillis() + 1000);
        String token = Jwts.builder()
                .setExpiration(expirationDate)
                .setClaims(claims)
                .signWith(SignatureAlgorithm.HS512, secret).compact();
        return token;
    }
    /**
     * 从令牌中获取数据声明
     *
     * @param token 令牌
     * @return 数据声明
     */
    private Claims parseToken(String token)
    {
        return Jwts.parser()
                .setSigningKey(secret)
                .parseClaimsJws(token)
                .getBody();
    }
}
