package com.lpd.SpringSecurity2023.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

@Service
public class JwtUtils {

    private String jwtSigningKey = "secret";

    //Trích xuất username từ token
    //Payload chứa các “Claims”.
    //Claims là một khối thông tin về một thực thể chẳng hạn người dùng là ai và một số metadata bắt buộc,
    //số còn lại tuân theo về JWT hợp lệ và đầy đủ thông tin: iss (issuer), iat (issued-at time) exp (expiration time), sub (subject), aud (audience), …
    //độ trễ phản hồi lại từ máy chủ khi tiếp nhận là do độ dài của Payload.
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    //Trích xuất ngày hết hạn của token
    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    //Trích xuất claim từ các claims trong payload của token
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token); //Lấy tất cả Claims trong payload
        return claimsResolver.apply(claims); //Trả về một Claim tương ứng với tham số (parameter) truyền vào
    }

    //Trích xuất tất cả các claims trong payload của token
    private Claims extractAllClaims(String token) {
        return Jwts.parser().setSigningKey(jwtSigningKey).parseClaimsJws(token).getBody();
    }

    //Kiểm tra token hết hạn
    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    //Tạo token từ tham số (parameter) truyền vào là UserDetails. Gọi phương thức createToken()
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails);
    }

    //Tạo token từ tham số (parameter) truyền vào là UserDetails và Map của claims cần truyền vào payload của token. Gọi phương thức createToken()
    public String generateToken(UserDetails userDetails, Map<String, Object> claims) {
        return createToken(claims, userDetails);
    }

    //createToken() để tạo ra token, gọi builder() (người xây dựng) từ lớp Jwts,
    //nó sẽ setClaims() là set các Claims vào payload của token.
    //setSubject() là set chủ đề là một thông tin nằm trong payload của token thường set thuộc tính (property) định danh (identify) của user như username, id, ...
    //.claims() là set claim authorities vào payload của token là để bỏ các quyền của user vào token
    //setIssuedAt() là set thông tin ban hành nằm trong payload của token, có thể là thông tin URL hoặc ngày tạo
    //setExpiration() là set thông tin ngày hết hạn nằm trong payload của token. Code set 24 giờ
    //signWith() là set chữ ký, là set loại thuật toán (algorithm) nằm trong Header của token và key để mã hóa.
    //compact() là tạo một mảng các biến định nghĩa trước đó
    private String createToken(Map<String, Object> claims, UserDetails userDetails) {

        return Jwts.builder().setClaims(claims)
                .setSubject(userDetails.getUsername())
                .claim("authorities", userDetails.getAuthorities())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + TimeUnit.HOURS.toMillis(24)))
                .signWith(SignatureAlgorithm.HS256, jwtSigningKey).compact();
    }

    //Kiểm tra token hợp lệ (Valid)
    //extractUsername(token) trích xuất username từ token, trích xuất bằng cách lấy từ subject trong payload của token
    //lấy username của token so sánh (compare) với username trong UserDetails là lên từ database và token chưa hết hạn
    public Boolean isTokenValid (String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}