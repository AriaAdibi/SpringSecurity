package com.testingground.springsecurity.security.authentication;

import com.testingground.springsecurity.security.JWTService;
import com.testingground.springsecurity.security.authentication.model.AuthenticationRequest;
import com.testingground.springsecurity.security.authentication.model.AuthenticationResponse;
import com.testingground.springsecurity.security.authentication.model.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.UserDetailsManager;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

  private final PasswordEncoder passwordEncoder;
  private final UserDetailsManager userDetailsManager;
  private final JWTService jWTService;
  private final AuthenticationManager authenticationManager;

  public AuthenticationResponse register(RegisterRequest registerRequest) {
    var user = User.builder() // TODO Use custom user with more information later
        .username(registerRequest.username())
        .password(passwordEncoder.encode(registerRequest.password()))
        // Same as role(); however, latter put a prefix defaulted to ROLE_
        .authorities(registerRequest.authorities())
        .build();

    userDetailsManager.createUser(user);
    // TODO Refresh? Save Token?
    return AuthenticationResponse.of(jWTService.generateToken(user));
  }

  public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
    /* Authentication Manager uses (only) DaoAuthenticationProvider. This provider like most,
     * returns UserDetails as Principal Object.
     */
    var authentication = authenticationManager.authenticate(
        new UsernamePasswordAuthenticationToken(authenticationRequest.username(), authenticationRequest.password()));

    if (authentication.getPrincipal() instanceof UserDetails userDetails) {
      // TODO Refresh? Revoke Tokens? Save Token?
      return AuthenticationResponse.of(jWTService.generateToken(userDetails));
    } else {
      throw new AuthenticationServiceException("Unsupported Authentication Principal Type");
    }
  }

  public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
    //TODO
  }

}
