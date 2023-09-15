package com.testingground.springsecurity.security;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import java.security.Key;
import java.sql.Date;
import java.time.Instant;
import java.util.Map;
import java.util.function.Function;

@Service
public class JWTService {

  private final Key SECRET_KEY;
  private final long DEFAULT_TOKEN_LONGEVITY_IN_NANOSECOND;

  public JWTService(
      @Value("${application.security.jwt.base64-aes256-encoded-secret-key}") String base64AES256EncodedSecretKey,
      @Value("${application.security.jwt.default-token-longevity}") long defaultTokenLongevity) {
    //    Keys.secretKeyFor(SignatureAlgorithm.HS256); Dynamic (on each run) key generator
    this.SECRET_KEY = Keys.hmacShaKeyFor(Decoders.BASE64.decode(base64AES256EncodedSecretKey));
    this.DEFAULT_TOKEN_LONGEVITY_IN_NANOSECOND = defaultTokenLongevity;
  }

  /* ************************************************** */
  /* Token Generation ********************************* */
  /* ************************************************** */

  public String generateToken(UserDetails userDetails) {
    return generateToken(userDetails, Map.of(), DEFAULT_TOKEN_LONGEVITY_IN_NANOSECOND);
  }

  public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims) {
    return generateToken(userDetails, extraClaims, DEFAULT_TOKEN_LONGEVITY_IN_NANOSECOND);
  }

  public String generateToken(UserDetails userDetails, Map<String, Object> extraClaims, long longevityInNanoSecond) {
    return Jwts.builder()
        .setSubject(userDetails.getUsername())
        .setIssuedAt(Date.from(Instant.now()))
        .setExpiration(Date.from(Instant.now().plusNanos(longevityInNanoSecond)))
        .setClaims(extraClaims)
        .signWith(SECRET_KEY)
        .compact();
  }

  /* ************************************************** */
  /* Claim Extraction ********************************* */
  /* ************************************************** */

  public Claims extractAllClaims(String token) {
    return Jwts.parserBuilder()
        .setSigningKey(SECRET_KEY)
        .build()
        .parseClaimsJws(token)
        .getBody();
  }

  public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    return claimsResolver.apply(extractAllClaims(token));
  }

  public String extractUsername(String token) {
    return extractClaim(token, Claims::getSubject);
  }

  private Instant extractExpiration(String token) {
    return extractClaim(token, Claims::getExpiration).toInstant();
  }

  /* ************************************************** */
  /* Token Validation ********************************* */
  /* ************************************************** */

  public boolean isTokenValid(String token, UserDetails userDetails) {
    final String username = extractUsername(token);
    return (username.equals(userDetails.getUsername())) && !isTokenExpired(token);
  }

  private boolean isTokenExpired(String token) {
    return extractExpiration(token).isBefore(Instant.now());
  }

}
