package org.fergonco.blog.springtokenbasedauth;

import java.util.Base64;
import java.util.Date;

import javax.annotation.PostConstruct;
import javax.servlet.http.HttpServletRequest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

public class JWTProvider {

    private static final SignatureAlgorithm ALGORITHM = SignatureAlgorithm.HS256;

    /**
     * THIS IS NOT A SECURE PRACTICE! For simplicity, we are storing a static key
     * here. Ideally, in a microservices environment, this key would be kept on a
     * config-server.
     */
    private String secretKey = "mysecret";

    private long validityInMilliseconds = 60000; // 1minute

    @Autowired
    private UserDetailsService myUserDetails;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(String username) {
        Date now = new Date();
        Date expiration = new Date(now.getTime() + validityInMilliseconds);
        return Jwts.builder()//
                .setSubject(username)//
                .setIssuedAt(now)//
                .setExpiration(expiration)//
                .signWith(ALGORITHM, secretKey)//
                .compact();
    }

    public Authentication getAuthentication(String tokenString) {
        Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(tokenString);
        String user = claims.getBody().getSubject();
        UserDetails userDetails = myUserDetails.loadUserByUsername(user);
        UsernamePasswordAuthenticationToken ret = new UsernamePasswordAuthenticationToken(userDetails, "",
                userDetails.getAuthorities());
        return ret;
    }

    public String getRefreshToken(String tokenString) {
        Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(tokenString);
        String user = claims.getBody().getSubject();
        Date expiration = claims.getBody().getExpiration();
        if (new Date(new Date().getTime() + validityInMilliseconds / 10).after(expiration)) {
            return createToken(user);
        }
        return null;
    }

    public String getToken(HttpServletRequest req) {
        String bearerToken = req.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7, bearerToken.length());
        }
        return null;
    }

    public boolean validateToken(String token) {
        Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token);
        if (SignatureAlgorithm.forName(claims.getHeader().getAlgorithm()) != ALGORITHM) {
            return false;
        }
        return true;
    }
}
