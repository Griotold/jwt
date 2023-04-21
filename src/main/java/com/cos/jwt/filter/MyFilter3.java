package com.cos.jwt.filter;

import javax.servlet.*;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {
    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
                         FilterChain chain) throws IOException, ServletException {

        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse res = (HttpServletResponse) response;

        req.setCharacterEncoding("UTF-8");

        // 토큰 : kandela
        // id, pw로 정상 로그인을 하면, 토큰을 생성해서 응답해준다.
        // 토큰이 다시 서버에 넘어 올때 내가 만든 토큰인지 검증만 해준다.(RSA, HS256)
        if (req.getMethod().equals("POST")) {
            System.out.println("필터 3");
            System.out.println("POST 요청 됨");
            String headerAuth = req.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);

            if (headerAuth.equals("kandela")) {
                chain.doFilter(req, res);
            } else {
                PrintWriter out = res.getWriter();
                out.println("Not authenticated");
            }
        }
    }
}
