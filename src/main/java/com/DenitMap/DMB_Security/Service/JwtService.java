package com.DenitMap.DMB_Security.Service;


import com.DenitMap.DMB_Security.Model.User;
import com.DenitMap.DMB_Security.Security.KeyUtils;
import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.time.Instant;
import java.util.Date;

@Service
@RequiredArgsConstructor
public class JwtService {


    private final KeyUtils keyUtils;

    @Value("${jwt.access-expiration-ms}")
    private long accessExpMs;


    @Value("${jwt.refresh-expiration-ms}")
    private long refreshExpMs;

    public String generateToken(User user){
        PrivateKey privateKey = keyUtils.loadPrivateKey();

        Instant now = Instant.now();
        Instant exp = now.plusMillis(accessExpMs);

        return Jwts.builder().setSubject(user.getEmail()).setIssuedAt(Date.from(now))
                .setExpiration(Date.from(exp)).claim("uuid",user.getId()).claim("firstName", user.getFirstName())
                .claim("roles","USER").claim("type","access").signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }


    public String generateRefreshToken(User user){
        PrivateKey privateKey = keyUtils.loadPrivateKey();

        Instant now = Instant.now();
        Instant exp = now.plusMillis(refreshExpMs);

        return Jwts.builder().setSubject(user.getEmail()).setIssuedAt(Date.from(now)).setExpiration(Date.from(exp))
                .claim("type","refresh").signWith(privateKey, SignatureAlgorithm.RS256).compact();
    }

    public Claims validateAndGetClaims(String jwt){
        try {
            PublicKey publicKey = keyUtils.loadPublicKey();
            return Jwts.parserBuilder().setSigningKey(publicKey).build().parseClaimsJws(jwt).getBody();
        } catch (Exception e){
            throw e;
        }
    }


}