package com.truongbn.security.service.impl;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.StringJoiner;
import java.util.function.Function;

import com.truongbn.security.entities.User;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import com.truongbn.security.service.JwtService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.util.CollectionUtils;

@Service
public class JwtServiceImpl implements JwtService {
//    @Value("${token.signing.key}")
    private String jwtSigningKey = "413F4428472B4B6250655368566D5970337336763979244226452948404D6351";
    @Override
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    @Override
    public String generateToken(UserDetails userDetails) {
        Map<String, Object> extraClaims = new HashMap<>();
        if(!CollectionUtils.isEmpty(userDetails.getAuthorities())){
            extraClaims.put("roles",userDetails.getAuthorities());
        }
        return generateToken(extraClaims, userDetails);
    }

    @Override
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    private <T> T extractClaim(String token, Function<Claims, T> claimsResolvers) {
        final Claims claims = extractAllClaims(token);
        return claimsResolvers.apply(claims);
    }

    private String generateToken(Map<String, Object> extraClaims, UserDetails userDetails) {
        return Jwts.builder()
                .setClaims(extraClaims)
                //"sub" là tên người dùng(ở đây là email) từ userDetails.
                .setSubject(userDetails.getUsername())
                //trường "iat" là ngày tạo token
                .setIssuedAt(new Date(System.currentTimeMillis()))
                //trường "exp" là ngày hết hạn
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                //secret key:
                .signWith(getSigningKey(), SignatureAlgorithm.HS256).compact();
    }
    //Thoa: thêm role vào phần payload của token JWT:
//    private String getScope(User user){
//        StringJoiner stringJoiner = new StringJoiner(" ");
//        if(!CollectionUtils.isEmpty(user.getRoles())){
//            user.getRoles().forEach(stringJoiner::add);
//        }
//        return stringJoiner.toString();
//    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parserBuilder().setSigningKey(getSigningKey()).build().parseClaimsJws(token)
                .getBody();
    }

    private Key getSigningKey() {
        byte[] keyBytes = Decoders.BASE64.decode(jwtSigningKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }
}
