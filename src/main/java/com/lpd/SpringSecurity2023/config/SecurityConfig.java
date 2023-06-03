package com.lpd.SpringSecurity2023.config;

import com.lpd.SpringSecurity2023.dao.UserDao;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.util.*;

@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthFilter jwtAuthFilter;
    private final UserDao userDao;

    //1/Chuỗi bộ lọc
    //2/.sessionManagement() là quan lý phiên
    //3/.sessionCreationPolicy(SessionCreationPolicy.STATELESS) là chính sách tạo phiên (session creation policy) để xử lý (handle) phiên (session) trong security
    //Config này cực kì quan trong vì để xác thực user, khi xác thực lần đầu tiên phiên sẽ luôn ở trạng thái đã xác thực (authenticated)
    //Chúng ta có thể kiểm soát chính xác thời điểm phiên của chúng ta được tạo và cách Spring Security sẽ tương tác với nó
    //ngoài ra còn có các chính sách như:
    //STATELESS là Spring Security sẽ không tạo hoặc sử dụng phiên nào.
    //ALWAYS là một phiên sẽ luôn được tạo nếu một phiên chưa tồn tại.
    //IF_REQUIRED là phiên sẽ chỉ được tạo nếu được yêu cầu (mặc định).
    //NEVER là framework sẽ không bao giờ tự tạo phiên, nhưng nó sẽ sử dụng phiên nếu nó đã tồn tại.
    //4/.authenticationProvider là nhà cung cấp xác thực
    //5/.addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class) đưa bộ lọc vào
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .authorizeRequests()
                .antMatchers("/**/auth/**")
                .permitAll()
                .anyRequest()
                .authenticated()
                .and()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authenticationProvider(authenticationProvider())
                .addFilterBefore(jwtAuthFilter, UsernamePasswordAuthenticationFilter.class);
        return http.build();
    }

    //Trong AuthenticationManager lại sử dụng AuthencationProvider (mặc định là DaoAuthenticationProvider) để thực hiện validate thông tin người dùng.
    //DaoAuthenticationProvider sẽ call UserDetailService để xác thực thông tin người dùng.
    @Bean
    public AuthenticationProvider authenticationProvider() {
        final DaoAuthenticationProvider authenticationProvider = new DaoAuthenticationProvider();
        authenticationProvider.setUserDetailsService(userDetailsService()); //Set UserDetailsService mà chúng ta mới custom bên dưới
        authenticationProvider.setPasswordEncoder(passwordEncoder()); //Set thuật toán mã hóa password
        return authenticationProvider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return  config.getAuthenticationManager();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return NoOpPasswordEncoder.getInstance(); //Có thể dùng class NoOpPasswordEncoder implements từ PasswordEncoder để không mã hóa password
        //return new BCryptPasswordEncoder(); //Để mã hóa password
    }

    //Ghi đè lại phương thức loadUserByUsername() của class UserDetailsService để nó load User của chúng ta
    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService() {
            @Override
            public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException {
                return userDao.findUserByEmail(email);
            }
        };
    }
}
