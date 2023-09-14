package com.testingground.springsecurity.security.authentication.model;

import java.util.Objects;

public record RegisterRequest(
    String firstName,
    String lastName,
    String email,
    String username,
    String password) {
  public RegisterRequest {
    Objects.requireNonNull(firstName, "First name should be provided.");
    Objects.requireNonNull(lastName, "Last name should be provided.");
    Objects.requireNonNull(email, "Email should be provided.");
    Objects.requireNonNull(username, "Username should be provided.");
    Objects.requireNonNull(password, "Password should be provided.");
    validateEmailAddress();
  }

  private void validateEmailAddress() { // TODO
  }
}
