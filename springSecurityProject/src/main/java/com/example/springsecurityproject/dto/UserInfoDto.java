package com.example.springsecurityproject.dto;

import lombok.Getter;
import lombok.Setter;

@Getter @Setter
public class UserInfoDto {

    private String userId;
    private String userName;
    private String password;
    private String email;
    private String roles;
}
