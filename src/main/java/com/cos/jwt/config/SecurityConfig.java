package com.cos.jwt.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.web.header.writers.frameoptions.WhiteListedAllowFromStrategy;
import org.springframework.security.web.header.writers.frameoptions.XFrameOptionsHeaderWriter;

import java.util.Arrays;
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .antMatchers(
                        "/h2-console/**"    // 여기!
                ).permitAll()
                .anyRequest().authenticated()
                .and()
                .formLogin()
                .and()
                .csrf().disable()  // CSRF 보호 해제
                .headers().frameOptions().disable();  // X-Frame-Options 보호 해제

    }
}
