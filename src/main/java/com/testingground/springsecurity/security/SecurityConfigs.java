package com.testingground.springsecurity.security;

import com.testingground.springsecurity.security.authentication.JWTAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseBuilder;
import org.springframework.jdbc.datasource.embedded.EmbeddedDatabaseType;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.HeadersConfigurer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.jdbc.JdbcDaoImpl;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
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

  @Bean
  public DataSource dataSource() {
    return new EmbeddedDatabaseBuilder()
        .setType(EmbeddedDatabaseType.H2)
        .addScript(JdbcDaoImpl.DEFAULT_USER_SCHEMA_DDL_LOCATION)
        .build(); // Creating the default user/authorities tables
  }

  /* The following makes the AuthenticationManager "Globally" (Spring context) accessible.
   * It can be locally accessed like (HttpSecurity)http.getSharedObject(AuthenticationManager.class);
   * To configure the HttpSecurity with a custom AuthenticatorManager:
   * 1. Have a look at the official migration tutorial and the use of
   * AbstractHttpConfigurer<MyCustomDsl, HttpSecurity> which can be applied to http at the end with http.apply()
   * 2. Just use the .authenticationManager() method to set the new custom AuthenticationManager.
   */
  @Bean
  public AuthenticationManager authenticationManager(AuthenticationConfiguration authConfig) throws Exception {
    return authConfig.getAuthenticationManager();
  }

  /* AuthenticationManager can have a (ordered) list of authentication provider which it calls in order.
   * Both AuthenticationManager and Provider can be added to httpSecurity.
   */
  @Bean
  public AuthenticationProvider authenticationProvider(UserDetailsService userDetailsService) {
    var authProvider = new DaoAuthenticationProvider();
    authProvider.setUserDetailsService(userDetailsService);
    return authProvider;
  }

  /* Some Authentication Providers, including DaoAuthenticationProvider, require to have userDetailsService.
   * I provide UserDetailsManager instead which extends UserDetailsService. With Manager user creation,
   * deletion, etc. can also be done.
   */
  @Bean
  public UserDetailsService userDetailsService(DataSource dataSource) {
    var jdbcUserDetailsManager = new JdbcUserDetailsManager(dataSource);
    // Can create default users here:
    jdbcUserDetailsManager.createUser(
        User.withUsername("AriaTheGreat")
            /* BCryptPasswordEncoder of "StrongPassword". "{bcrypt}" is added because DelegatingPasswordEncoder
             * is used, and the algorithm needs to be provided. For more info refer to DelegatingPasswordEncoder.
             *
             * It is recommended that if user is created with code like this to have the password
             * encoded externally, the reasoning is that if not the password is compiled into the
             * source code and then is included in memory at the time of creation. This means there
             * are still ways to recover the plain text password making it unsafe.
             */
            .password("{bcrypt}$2a$12$v4qupXChBvh0htucys/CDedGtyeREbatnOwgLruKkG5IeK8Vr9gli")
            .authorities("KingOfKings") // = roles() but in roles the strings get the (modifiable) prefix ROLE_
            .build());
    return jdbcUserDetailsManager;
  }

  @Bean
  public PasswordEncoder passwordEncoder() {
    /* Instead of using one password encoder, using the default DelegatingPasswordEncoder.
     * Of course, custom DelegatingPasswordEncoder can be created as well. The encoding,
     * saves the algorithm in the encoded String like {alg}hashCode. Format also can be changed.
     */
    return PasswordEncoderFactories.createDelegatingPasswordEncoder();
  }

  @Bean
  MvcRequestMatcher.Builder mVCRequestMatcherBuilder(HandlerMappingIntrospector introspector) {
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
        .authorizeHttpRequests(authorizeHttpRequestsCustomizer ->
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
         * UsernamePasswordAuthenticationFilter which is run after sees that the user is not authenticated and
         * will do its routing.
         */
        // Authentication Providers
        .authenticationProvider(authenticationProvider)
        // Filters
        .addFilterBefore(jWTAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)
        .build();
  }

}
