package com.leaf.mapper;

import com.leaf.entity.AccountDetails;
import org.apache.ibatis.annotations.Mapper;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * @Auther:
 * @Desc: 用户信息Mapper
 */
@Mapper
@Component
public interface MyUserDetailsServiceMapper {

    /**
     * 根据username查询用户信息.
     */
    @Select("SELECT username,password\n" +
            "FROM sys_user u\n" +
            "WHERE u.username = #{username}")
    AccountDetails findByUserName(@Param("username") String username);

//    @Select("SELECT * FROM sys_user u WHERE u.username = #{username}")
//    AccountDetails findByUserName(@Param("username") String username);

    /**
     * 根据userID查询用户角色列表.
     */
    @Select("SELECT code\n" +
            "FROM sys_role r\n" +
            "LEFT JOIN sys_user_role ur ON r.id = ur.role_id\n" +
            "LEFT JOIN sys_user u ON u.id = ur.user_id\n" +
            "WHERE u.username = #{username}")
    List<String> findRoleByUserName(@Param("username") String username);


    /**
     * 根据用户角色查询用户菜单权限.
     */
    @Select({
            "<script>",
            "SELECT url ",
            "FROM sys_menu m ",
            "LEFT JOIN sys_role_menu rm ON m.id = rm.menu_id ",
            "LEFT JOIN sys_role r ON r.id = rm.role_id ",
            "WHERE r.role_code IN ",
            "<foreach collection='roleCodes' item='roleCode' open='(' separator=',' close=')'>",
            "#{roleCode}",
            "</foreach>",
            "</script>"
    })
    List<String> findMenuByRoleCodes(@Param("roleCodes") List<String> roleCodes);


    /**
     * 根据用户角色查询用户接口访问权限.
     */
    @Select({
            "<script>",
            "SELECT perms ",
            "FROM sys_menu a ",
            "LEFT JOIN sys_role_menu ra ON a.id = ra.menu_id ",
            "LEFT JOIN sys_role r ON r.id = ra.role_id ",
            "WHERE r.code IN ",
            "<foreach collection='roleCodes' item='roleCode' open='(' separator=',' close=')'>",
            "#{roleCode}",
            "</foreach>",
            "</script>"
    })
    List<String> findApiByRoleCodes(@Param("roleCodes") List<String> roleCodes);

}