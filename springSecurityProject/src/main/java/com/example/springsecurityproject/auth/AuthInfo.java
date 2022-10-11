package com.example.springsecurityproject.auth;

import com.example.springsecurityproject.dto.UserInfoDto;
import lombok.Getter;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;

@Slf4j
@Getter
@RequiredArgsConstructor
public class AuthInfo implements UserDetails {

    private final UserInfoDto userInfoDto;

    /**
     * 로그인한 사용자 권한 부여
     * @return
     */
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {

        Set<GrantedAuthority> requestSet = new HashSet<>();

        // DB의 USER_INFO 테이블에 저장된 권한 정보를 Spring Security에 반영한다.
        String roles = userInfoDto.getRoles();

        // DB에 저장된 Role이 있는 경우에만 실행
        if (roles.length() > 0) {
            for (String role : roles.split(",")) {
                requestSet.add(new SimpleGrantedAuthority(role));
            }
        }
        return requestSet;
    }

    /**
     * 사용자의 password 반환
     * @return
     */
    @Override
    public String getPassword() {
        return userInfoDto.getUserId();
    }

    /**
     * 사용자의 ID 반환 : unique 값
     * @return
     */
    @Override
    public String getUsername() {
        return userInfoDto.getUserId();
    }

    /**
     * 계정 만료 여부 반환
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return false; // true -> 만료되지 않음
    }

    /**
     * 계정 잠금 여부 반환
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return false; // true -> 잠금되지 않음
    }

    /**
     * 패스워드 만료 여부 반환
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return false; // true -> 만료되지 않았음
    }

    /**
     * 계정 사용 가능 여부 반환
     * @return
     */
    @Override
    public boolean isEnabled() {
        return false; // true -> 사용 가능
    }
}
