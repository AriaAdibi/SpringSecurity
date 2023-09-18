package com.testingground.springsecurity.security.authentication;

import com.testingground.springsecurity.security.JWTService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.lang.NonNull;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JWTAuthenticationFilter extends OncePerRequestFilter {

  private final JWTService jWTService;
  private final UserDetailsService userDetailsService;

  @Override
  protected void doFilterInternal(
      @NonNull HttpServletRequest request,
      @NonNull HttpServletResponse response,
      @NonNull FilterChain filterChain) throws ServletException, IOException {
    if (request.getServletPath().contains("/api/v1/auth")) {
      filterChain.doFilter(request, response);
      return;
    }

    final String authHeader = request.getHeader("Authorization");
    /* If the Authorization header is missing, or it does not start with Bearer
     * (required for JWT token) skipping this filter in the hope that authentication
     * can be done in another way (filter).
     */
    if (authHeader == null || !authHeader.startsWith("Bearer ")) {
      filterChain.doFilter(request, response);
      return;
    }

    final var jWSToken = authHeader.substring(7);
    final var username = jWTService.extractUsername(jWSToken);
    /* 1. If username is not in the payload skip hoping that another filter will do
     * authentication with other information.
     * 2. Only start the authentication process if the user is not already authenticated
     */
    if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
      var userDetails = this.userDetailsService.loadUserByUsername(username);
      // TODO
      //      var isTokenValid = tokenRepository.findByToken(jwt)
      //          .map(t -> !t.isExpired() && !t.isRevoked())
      //          .orElse(false);
      if (jWTService.isTokenValid(jWSToken, userDetails)) {
        var authToken = new UsernamePasswordAuthenticationToken(
            userDetails, null, userDetails.getAuthorities());
        /* Set additional web details appearing in request. In this case:
         * Records the remote address and will also set the session id if a session already exists (it won't create one).
         */
        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authToken);
      }
    }

    filterChain.doFilter(request, response);
  }
}
