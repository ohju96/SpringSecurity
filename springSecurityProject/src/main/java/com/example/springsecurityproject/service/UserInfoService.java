package com.example.springsecurityproject.service;

import com.example.springsecurityproject.dto.UserInfoDto;
import org.springframework.security.core.userdetails.UserDetailsService;

public interface UserInfoService extends UserDetailsService {

    // 회원 가입하기 : 회원정보 등록하기
    int insertUserInfo(UserInfoDto userInfoDto) throws Exception;

}
