package com.cos.jwt.config;

import com.cos.jwt.config.jwt.JwtAuthenticationFilter;
import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter3;
import lombok.RequiredArgsConstructor;

import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.context.SecurityContextPersistenceFilter;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;
import org.springframework.web.filter.CorsFilter;

import java.util.Arrays;
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final CorsFilter corsFilter;
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // Security 필터들이 동작하기 전에 내가 만든 필터가 동작해야 한다.
        http.addFilterBefore(new MyFilter3(), SecurityContextPersistenceFilter.class);
        // JWT 기본 사용법
        // csrf, STATELESS, formLogin, httpBasic은 모두 disable 처리
        http.csrf().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http
                .addFilter(corsFilter)
                .formLogin().disable()
                .httpBasic().disable()
                .addFilter(new JwtAuthenticationFilter(authenticationManager()))
                .authorizeRequests()
                .antMatchers("/api/v1/user/**")
                .access("hasRole('ROLE_USER') or hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/manager/**")
                .access("hasRole('ROLE_MANAGER') or hasRole('ROLE_ADMIN')")
                .antMatchers("/api/v1/admin/**")
                .access("hasRole('ROLE_ADMIN')")
                .antMatchers(
                        "/h2-console/**"
                ).permitAll();

    }
}
