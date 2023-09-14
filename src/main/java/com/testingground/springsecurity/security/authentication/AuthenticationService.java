package com.testingground.springsecurity.security.authentication;

import com.testingground.springsecurity.security.authentication.model.AuthenticationRequest;
import com.testingground.springsecurity.security.authentication.model.AuthenticationResponse;
import com.testingground.springsecurity.security.authentication.model.RegisterRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.stereotype.Service;

@Service
public class AuthenticationService {

  public AuthenticationResponse register(RegisterRequest registerRequest) {
    return null; // TODO
  }

  public AuthenticationResponse authenticate(AuthenticationRequest authenticationRequest) {
    return null; // TODO
  }

  public void refreshToken(HttpServletRequest request, HttpServletResponse response) {
    //TODO
  }

}
