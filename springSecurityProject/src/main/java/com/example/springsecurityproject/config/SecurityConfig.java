package com.example.springsecurityproject.config;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@Slf4j
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf();


        http.authorizeRequests()
                .antMatchers("/user/**", "/notice/**").hasAnyAuthority("ROLE_USER")
                .antMatchers("/admin/**").hasAnyAuthority("ROLE_ADMIN")
                .anyRequest().authenticated()
                .anyRequest().permitAll()
                ;

        http.formLogin()
                .loginPage("/ss/loginForm")
                .loginProcessingUrl("/ss/loginProc")
                .usernameParameter("user_id")
                .passwordParameter("password")
                .successForwardUrl("/ss/loginSuccess")
                .failureForwardUrl("/ss/loginFail")
                ;

        http.logout()
                .logoutUrl("/logout")
                .logoutSuccessUrl("/")
                ;
    }
}
