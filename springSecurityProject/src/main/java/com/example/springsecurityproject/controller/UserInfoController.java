package com.example.springsecurityproject.controller;

import com.example.springsecurityproject.dto.UserInfoDto;
import com.example.springsecurityproject.service.UserInfoService;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.ModelMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpServletRequest;

@Slf4j
@RequestMapping(value = "/ss")
@RequiredArgsConstructor
@RestController
public class UserInfoController {
    private final UserInfoService userInfoService;
    private final PasswordEncoder passwordEncoder;


}
