package com.testingground.springsecurity.security.authentication.model;

import java.util.Objects;

public record AuthenticationRequest(String username, String password) {
  public AuthenticationRequest {
    Objects.requireNonNull(username, "Username should be provided.");
    Objects.requireNonNull(password, "Password should be provided.");
  }
}
