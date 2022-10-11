package com.example.springsecurityproject.service.impl;

import com.example.springsecurityproject.auth.AuthInfo;
import com.example.springsecurityproject.dto.UserInfoDto;
import com.example.springsecurityproject.repository.UserInfoRepository;
import com.example.springsecurityproject.repository.entity.UserInfoEntity;
import com.example.springsecurityproject.service.UserInfoService;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
@Service
public class UserInfoServiceImpl implements UserInfoService {

    private final UserInfoRepository userInfoRepository;

    @Override
    public int insertUserInfo(UserInfoDto userInfoDto) throws Exception {

        int res = 0; // 성공 : 1, 중복 : 2, 기타 : 0

        String userId = userInfoDto.getUserId();
        String userName = userInfoDto.getUserName();
        String password = userInfoDto.getPassword();
        String email = userInfoDto.getEmail();
        String roles = userInfoDto.getRoles();

        log.info("userId : {}", userId);
        log.info("userName : {}", userName);
        log.info("password : {}", password);
        log.info("email : {}", email);

        // 회원 가입 중복 방지를 위해 DB에서 데이터 조회
        Optional<UserInfoEntity> requestEntity = userInfoRepository.findByUserId(userId);

        if (requestEntity.isPresent()) {
            res = 2;
        } else {
            UserInfoEntity createUserInfoEntity = UserInfoEntity.builder()
                    .userId(userId)
                    .userName(userName)
                    .password(password)
                    .email(email)
                    .roles(roles)
                    .build();

            userInfoRepository.save(createUserInfoEntity);

            if (requestEntity.isPresent()) {
                res = 1;
            } else {
                res = 0;
            }
        }
        return res;
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        UserInfoEntity requestEntity = userInfoRepository.findByUserId(username)
                .orElseThrow(() -> new UsernameNotFoundException(username + "Not Found User"));

        UserInfoDto requestDto = new ObjectMapper().convertValue(requestEntity, UserInfoDto.class);

        return new AuthInfo(requestDto);
    }
}
