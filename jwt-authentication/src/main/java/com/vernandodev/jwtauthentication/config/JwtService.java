package com.vernandodev.jwtauthentication.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Service
public class JwtService {

    // todo Validate JWT
    // create SECRET_KEY with Encryption Key Generator
    // add dependency io.jsonwebtoken (jjwt-api, jjwt-impl, jjwt-jackson)
    private static final String SECRET_KEY = "2948404D6251655468576D5A7134743777217A25432A462D4A614E645266556A";
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getSignInKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    // the signInKey is used to created the signature part of the JWT which is used to verify that the sender of JWT is
    // who it claims to be and ensure that the message wasn't changed along the way
    // conclusion : so we want to ensure that the same person that is sending this JWT key is the one that claims who to be
    private Key getSignInKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        // todo Creates a new SecretKey instance for use with HMAC-SHA algorithms based on the specified key byte array.
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // created method can extract a single claim that we pass
    // todo generic method
    public<T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    // todo generate token with extraClaims and userDetails
    public String generateToken(
            Map<String, Object> extraClaims,
            UserDetails userDetails
    ) {
        return Jwts
                .builder()
                .setClaims(extraClaims)
                .setSubject(userDetails.getUsername())
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 24))
                .signWith(getSignInKey(), SignatureAlgorithm.HS256)
                .compact();
    }

    // todo generate token only with userDetails
    public String generateToken(UserDetails userDetails) {
        return generateToken(new HashMap<>(), userDetails);
    }

    // Implement a method that will validate a token
    // todo validate jwt, have 2 parameters token and userDetails
    // todo check if username equals in userDetails && token expired
    public boolean isTokenValid(String token, UserDetails userDetails) {
        final String username = extractUsername(token);
        return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
    }

    // todo check isTokenExpired in method extractExpiration from token that we have
    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    // todo create extractExpiration
    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
