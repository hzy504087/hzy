package com.leaf.entity;

import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import com.leaf.config.WebSecurityConfig;
//import com.leaf.service.SysUserService;
import com.leaf.mapper.MyUserDetailsServiceMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Component;

import javax.annotation.Resource;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AccountDetailsService implements UserDetailsService {
    @Autowired
    private MyUserDetailsServiceMapper myUserDetailsServiceMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        //1.加载基础用户信息
        AccountDetails accountDetails = myUserDetailsServiceMapper.findByUserName(username);
        //加载用户角色列表
        List<String> roleCodes = myUserDetailsServiceMapper.findRoleByUserName(username);

        if (roleCodes!=null&&roleCodes.size() > 0) {
            //3.通过用户角色列表加载用户的资源权限列表
            List<String> authorizes = myUserDetailsServiceMapper.findApiByRoleCodes(roleCodes);
            //4.角色是一个特殊的权限，SpringSecurity规定对于角色需要加上ROLE_前缀
            roleCodes = roleCodes.stream()
                    .map(rc -> "ROLE_" + rc)
                    .collect(Collectors.toList());

            authorizes.addAll(roleCodes);
            //5.将用户权限列表赋给用户信息
            accountDetails.setAuthorities(
                    AuthorityUtils.commaSeparatedStringToAuthorityList(
                            String.join(",", authorizes)
                    )
            );
        }
        return accountDetails;
    }

}
