package com.testingground.springsecurity.security;

import com.testingground.springsecurity.security.authentication.JWTAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.servlet.util.matcher.MvcRequestMatcher;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.servlet.handler.HandlerMappingIntrospector;

import javax.sql.DataSource;

import static org.springframework.security.config.http.SessionCreationPolicy.STATELESS;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity
@RequiredArgsConstructor
class SecurityConfigs {

  private final DataSource dataSource;

  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }

  /* AuthenticationManager can have a (ordered) list of authentication provider which it calls in order.
   * Both AuthenticationManager and Provider can be added to httpSecurity.
   */
  @Bean
  public AuthenticationProvider authenticationProvider() {
    var authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService());
    return authProvider;
  }

  /* Some Authentication Providers, including DaoAuthenticationProvider, require to have userDetailsService. */
  @Bean
  public UserDetailsService userDetailsService() {
    return new JdbcUserDetailsManager(this.dataSource);
  }

  @Bean
  MvcRequestMatcher.Builder mvc(HandlerMappingIntrospector introspector) {
    return new MvcRequestMatcher.Builder(introspector);
  }

  /* MvcRequestMatcher.Builder mvc needed to be autowired as well because requestMachers() had this problem:
   * "There is more than one mappable servlet in your servlet context", one was "/" the other "/h2-console/".
   * To specify exactly that Spring MVC RequestMatcher is used this bean creation and autowiring is done.
   */
  @Bean
  public SecurityFilterChain securityFilterChain(
      HttpSecurity httpSecurity,
      AuthenticationProvider authenticationProvider,
      JWTAuthenticationFilter jWTAuthenticationFilter,
      MvcRequestMatcher.Builder mVCRequestMatcherBuilder) throws Exception {
    return httpSecurity
        /* Not needed since JWT tokens are send via Authentication Header (Custom header with no mechanism)
        as opposed to with Cookies. Cookies are also HTTP header; however, with some preloaded operations
        on browsers. Cookies can be set by Server, saved by browser and then AUTO-SENT by the browser. This
        Auto sending occurs even if the request to server comes from other website (CSRF/XSRF).

        More Info:
        1. There are mechanism to protect cookies CSRF.
        2. Cookie can be marked as httpOnly thus prevent client JavaScript access. Helping with
        XSS (Cross Site Scripting) attacks.
        3. Cookies are domain specific.
        */
        .csrf(AbstractHttpConfigurer::disable)
        /* By default, Spring Security disables rendering within an iframe because allowing a webpage to be
         * added to a frame can be a security issue, for example Clickjacking. Since H2 console runs within a
         * frame so while Spring security is enabled, frame options has to be disabled explicitly, in order to
         * get the H2 console working.
         *
         * In general there are two possible directives for X-Frame-Options, which are DENY or SAMEORIGIN,
         * The FrameOption either needs to be disabled or changed to SameOrigin for h2-console to work properly.
         */
        .headers(headersCustomizer ->
            headersCustomizer.frameOptions(HeadersConfigurer.FrameOptionsConfig::sameOrigin))
        // Authorizations
        .authorizeHttpRequests(authorizeHttpRequestsCustomizer -> // TODO Add Roles and (READ/WRITE ..) Authority check
            authorizeHttpRequestsCustomizer
                // PermitAll() usually includes some static and documentation URI as well.
                .requestMatchers(
                    // The pattern is not part of Spring MVC, that is why antMacher is used instead.
                    AntPathRequestMatcher.antMatcher("/h2-console/**"),
                    mVCRequestMatcherBuilder.pattern("/api/v1/auth/**"),
                    /* Need to add this because for cases where there is error spring redirects to this URL,
                     * and if not permitted the FORBIDDEN error is encountered without explanation.
                     */
                    mVCRequestMatcherBuilder.pattern("/error/**"))
                .permitAll()
                .anyRequest().authenticated())
        // Session Management
        .sessionManagement(sessionManagementCustomizer ->
            // So that no session id is created and authentication become stateless
            sessionManagementCustomizer.sessionCreationPolicy(STATELESS))
        /* Multiple filter can be provided for different authentication/authorization strategies and different
         * AuthenticationProviders for the way authentication is made; for example, whether use is obtained by
         * DAO or LDAP. However, all is implementation and need dependent the differentiating line is a blurry.
         *
         * Here jWTAuthenticationFilter is first and if it did not authenticate a user
         * UsernamePasswordAuthenticationFilter which is run after sees that the user is not authenticated and will
         * do its routing.
         */
        // Authentication Providers
        .authenticationProvider(authenticationProvider)
        // Filters
        .addFilterBefore(jWTAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }

}
