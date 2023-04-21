package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.ArrayList;
import java.util.Collection;

public class PrincipalDetails implements UserDetails {

    private User user;

    public PrincipalDetails(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // 여기 람다표현식!
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(r -> {
            authorities.add(() -> r);
        });
        return null;
    }
    // 만약 자바 8 이전 버젼이라면 -> 익명 클래스를 사용한다.
//    @Override
//    public Collection<? extends GrantedAuthority> getAuthorities() {
//        Collection<GrantedAuthority> authorities = new ArrayList<>();
//        for (Role role : user.getRoleList()) {
//            GrantedAuthority authority = new GrantedAuthority() {
//                @Override
//                public String getAuthority() {
//                    return role;
//                }
//            };
//            authorities.add(authority);
//        }
//        return authorities;
//    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }
}
