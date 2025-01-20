## Explanation
## JWTAuthenticationFilter Class Documentation

**Package:** `genum.security.jwt`

**Class:** `JWTAuthenticationFilter`

**Extends:** `UsernamePasswordAuthenticationFilter`

**Description:** This class extends Spring Security's `UsernamePasswordAuthenticationFilter` to handle JWT (JSON Web Token) authentication.  It intercepts login requests, authenticates users using the provided credentials, and generates a JWT upon successful authentication.  The JWT is then included in the response header.  It also handles unsuccessful authentication attempts, returning appropriate error responses.

**Dependencies:**

* `com.auth0.jwt`: Library for JWT creation and verification.
* `com.fasterxml.jackson.databind`: Library for JSON processing.
* `genum.data.DTO.request.LoginDTO`: Data Transfer Object representing login request data.
* `genum.data.DTO.response.ResponseDTO`: Data Transfer Object representing successful login response.
* `genum.data.DTO.response.UnsuccessfulLoginDTO`: Data Transfer Object representing unsuccessful login response.
* `genumUser.GenumUser`: Represents a user entity.
* `genum.persistence.genumUserRepository.GenumUserRepository`: Repository for accessing user data.
* `genum.serviceimplementation.exception.UserNotFoundException`: Custom exception for user not found scenarios.
* `org.springframework.security.authentication.AuthenticationManager`:  Interface for authentication management.
* `org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter`: Base class for authentication filters.
* `lombok.extern.slf4j.Slf4j`: Lombok annotation for simplified logging.


**Constructor:**

```java
public JWTAuthenticationFilter(AuthenticationManager authenticationManager, ApplicationContext context)
```

* **`authenticationManager`:** An instance of `AuthenticationManager` used to authenticate user credentials.
* **`context`:** Spring's `ApplicationContext` to retrieve the `GenumUserRepository` bean.  This is used to fetch user details after successful authentication.

**Methods:**

**1. `attemptAuthentication(HttpServletRequest request, HttpServletResponse response)`:**

* **Overrides:** `UsernamePasswordAuthenticationFilter.attemptAuthentication`
* **Description:**  This method is called when a login request is received. It reads login credentials from the request body, creates a `UsernamePasswordAuthenticationToken`, and uses the `authenticationManager` to authenticate the user.
* **Throws:** `AuthenticationException`: If authentication fails.  A `RuntimeException` wrapping an `IOException` is thrown if the request body cannot be parsed.
* **Returns:** An `Authentication` object representing the authenticated user.

**2. `successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult)`:**

* **Overrides:** `UsernamePasswordAuthenticationFilter.successfulAuthentication`
* **Description:** This method is called after successful authentication.  It generates a JWT using the `auth0` library, including the user's email and an expiration time. The JWT is then added to the response header along with the user details.
* **Throws:** `IOException`: If there is an issue writing the response.


**3. `unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed)`:**

* **Overrides:** `UsernamePasswordAuthenticationFilter.unsuccessfulAuthentication`
* **Description:** This method is called if authentication fails. It sets the HTTP response status to `401 Unauthorized` and sends an error message to the client.
* **Throws:** `IOException`, `ServletException`: Standard exceptions for servlet processing.

**Constants:**

The class uses constants from `genum.security.constant.SecurityConstants`  (not shown in the provided code) for things like the JWT secret, header name, and token prefix.  These should be defined securely and appropriately for a production environment.


**Exception Handling:**

The `@ExceptionHandler(UserNotFoundException.class)` annotation in the original code is incorrectly placed.  Exception handlers should typically be declared at the controller level, not within a filter.  This should be removed and handled appropriately higher up in the application stack.  The `RuntimeException` thrown in `attemptAuthentication` should also be replaced with a more specific and informative exception.

**Security Considerations:**

* **Secret Key Management:** The JWT secret key (`SECRET`) must be stored securely and should not be hardcoded.  Consider using environment variables or a secrets management system.
* **Error Handling:** The error handling could be improved by providing more specific error messages and avoiding the use of generic exceptions like `RuntimeException`.
* **Input Validation:**  Add input validation to prevent common security vulnerabilities like SQL injection or cross-site scripting (XSS).

This improved documentation provides a clearer understanding of the `JWTAuthenticationFilter` class and its functionality, highlighting important security considerations and suggesting improvements to the original code.  Remember to thoroughly review and adapt this documentation to fit the specifics of your project.


## Class: JWTAuthenticationFilter

- Function: attemptAuthentication
- Variable: authenticationManager
- Variable: genumUserRepository


## File Content
package genum.security.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import genum.data.DTO.request.LoginDTO;
import genum.data.DTO.response.ResponseDTO;
import genum.data.DTO.response.UnsuccessfulLoginDTO;
import genumUser.GenumUser;
import genum.persistence.genumUserRepository.GenumUserRepository;
import genum.serviceimplementation.exception.UserNotFoundException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.context.ApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.ExceptionHandler;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.Date;

import static genum.security.constant.SecurityConstants.*;

@Slf4j
public class JWTAuthenticationFilter extends UsernamePasswordAuthenticationFilter {
    private final AuthenticationManager authenticationManager;
    private final GenumUserRepository genumUserRepository;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager, ApplicationContext context) {
        this.authenticationManager = authenticationManager;
        genumUserRepository = context.getBean(GenumUserRepository.class);
        setFilterProcessesUrl("/api/auth/login");
    }

    

    @Override
    @ExceptionHandler(UserNotFoundException.class)
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        try {
            LoginDTO credential = new ObjectMapper().readValue(request.getInputStream(), LoginDTO.class);
            return authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            credential.getEmail(),
                            credential.getPassword(),
                            new ArrayList<>())
            );
        } catch (IOException exception) {
            throw new RuntimeException("User does not exist");
        }
    }

    @Override
    @ExceptionHandler(UserNotFoundException.class)
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException {
        String token = JWT.create()
                .withSubject(((User) authResult.getPrincipal()).getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+ EXPIRATION_TIME))
                .sign(Algorithm.HMAC512(SECRET.getBytes(StandardCharsets.UTF_8)));
        ObjectMapper oMapper = new ObjectMapper();
        String email = ((User) authResult.getPrincipal()).getUsername();
        GenumUser genumUser = genumUserRepository.findByEmail(email);
        ResponseDTO responseDto = new ResponseDTO();
        responseDto.setGenumUser(genumUser);
        responseDto.setToken(token);
        logger.info(token);

        response.setHeader(HttpHeaders.CONTENT_TYPE, "application/json");
        response.addHeader(HEADER_STRING, TOKEN_PREFIX + token);
        response.getOutputStream().print("{ \"data\":"  + oMapper.writeValueAsString(responseDto) +  "}");
        response.flushBuffer();
    }
    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
        super.unsuccessfulAuthentication(request, response, failed);
        UnsuccessfulLoginDTO responseDetails = new UnsuccessfulLoginDTO(LocalDateTime.now(), "Incorrect email or password", "Bad request", "/api/auth/login");
        response.getOutputStream().print("{ \"message\":"  + responseDetails +  "}");
    }
}
