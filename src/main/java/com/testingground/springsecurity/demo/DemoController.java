package com.testingground.springsecurity.demo;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("api/v1/demo")
public class DemoController {

  @GetMapping("welcome-user")
  public ResponseEntity<String> welcomeUser() {
    return ResponseEntity.ok("Welcome User!");
  }

  @GetMapping("welcome-admin")
  public ResponseEntity<String> welcomeAdmin() {
    return ResponseEntity.ok("Welcome Admin!");
  }

}
