package com.example.basicsecurity;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;
import org.springframework.security.web.savedrequest.RequestCache;
import org.springframework.security.web.savedrequest.SavedRequest;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity // 웹 보안 활성화
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    UserDetailsService userDetailsService;

    // 사용자 추가
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //{noop}는 패스워드 암호화 알고리즘 방식을 프리픽스 형태로 정해준 것이다. 나중에 패스워드 매칭할 때 어떤 알고리즘을 사용했는지 체크해야 하기 떄문에 지정해야 한다. noop은 아무것도 하지 않는 것이다.
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS", "USER");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN", "SYS", "USER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers("/login").permitAll() //로그인 페이지는 인증을 받지 않아도 접근할 수 있게 한다.
                .antMatchers("/user").hasRole("USER") ///user 요청하면 USER인지 권한 심사를 하겠다.
                .antMatchers("/admin/pay").hasRole("ADMIN") // 구체적인 범위가 위로 가야지 우리가 원하는 정상적인 인가 처리가 된다.
                .antMatchers("/admin/**").access("hasRole('ADMIN') or hasRole('SYS')")
                .anyRequest().authenticated();

        http.formLogin()
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        RequestCache requestCache = new HttpSessionRequestCache(); //사용자가 요청한 정보 "/user" 리소스를 담아둔다.
                        SavedRequest savedRequest = requestCache.getRequest(request, response);
                        String redirectUrl = savedRequest.getRedirectUrl();
                        response.sendRedirect(redirectUrl); //인증에 성공한 다음에 세션에 저장되어 있던 이전에 요청 정보를 가져올 수 있게 처리한다.
                    }
                });

        http.exceptionHandling()
//                .authenticationEntryPoint(new AuthenticationEntryPoint() {
//                    @Override
//                    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
//                        response.sendRedirect("/login"); //인증 예외가 발생해서 로그인 페이지로 이동 , 우리가 만든 로그인 페이지로 이동한다.
//                    }
//                })
                .accessDeniedHandler(new AccessDeniedHandler() {
                    @Override
                    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
                        response.sendRedirect("/denied"); //인가 예외가 발생
                    }
                });
    }

    //    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http.authorizeRequests()
//                .anyRequest().authenticated();
//
//        http.formLogin();
//
//        // 동시 세션 제어
//        http.sessionManagement()
//                .maximumSessions(1)
//                .maxSessionsPreventsLogin(true);
//
//        // 세션 고정 보호
//        http.sessionManagement()
//                .sessionFixation().changeSessionId();
//
//    }


    //    @Override
//    protected void configure(HttpSecurity http) throws Exception {
//        http
//                .authorizeRequests()
//                .anyRequest().authenticated();
//        http
//                .formLogin()
////                .loginPage("/loginPage") //로그인 경로는 인증을 받지 않아도 접근이 가능하게 해야 한다. 아래 퍼밋올 설정을 한다.
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
////                .successHandler(new AuthenticationSuccessHandler() {
////                    @Override
////                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
////                        System.out.println("authentication : " + authentication.getName());
////                        response.sendRedirect("/");
////                    }
////                })
////                .failureHandler(new AuthenticationFailureHandler() {
////                    @Override
////                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
////                        System.out.println("exception : " + exception.getMessage());
////                        response.sendRedirect("/login");
////                    }
////                })
//                .permitAll()
//                ;
//        http
//                .logout()
//                .logoutUrl("/logout")
//                .logoutSuccessUrl("/login")
//                .addLogoutHandler(new LogoutHandler() {
//                    @Override
//                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
//                        HttpSession session = request.getSession();
//                        session.invalidate();
//                    }
//                })
//                .logoutSuccessHandler(new LogoutSuccessHandler() {
//                    @Override
//                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        response.sendRedirect("/login");
//                    }
//                })
//                .deleteCookies("remember-me")
//        .and()
//                .rememberMe()
//                .rememberMeParameter("remember")
//                .tokenValiditySeconds(3600)
//                .userDetailsService(userDetailsService)
//                ;
//
//    }
}
