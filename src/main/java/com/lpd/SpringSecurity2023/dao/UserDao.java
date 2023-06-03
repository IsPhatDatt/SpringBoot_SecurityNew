package com.lpd.SpringSecurity2023.dao;

import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Repository;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

@Repository
public class UserDao {

    //Tạo các đối tượng User của UserDetails
    private final static List<UserDetails> APPLICATION_USERS = Arrays.asList(
            new User(
                    "phatdatvn2001@gmail.com",
                    "123",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_ADMIN"))
            ),
            new User(
                    "phatdatvn102@gmail.com",
                    "123",
                    Collections.singleton(new SimpleGrantedAuthority("ROLE_USER"))
            )
    );

    //Tìm user trong danh sách APPLICATION_USERS
    public UserDetails findUserByEmail(String email) {
        return APPLICATION_USERS
                .stream()
                .filter(u -> u.getUsername().equals(email))
                .findFirst()
                .orElseThrow(() -> new UsernameNotFoundException("No user was found"));
    }
}
