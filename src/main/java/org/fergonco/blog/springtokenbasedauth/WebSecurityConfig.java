package org.fergonco.blog.springtokenbasedauth;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.Http403ForbiddenEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
@EnableWebSecurity
public class WebSecurityConfig extends WebSecurityConfigurerAdapter {

    @Autowired
    private JWTProvider jwtProvider;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().mvcMatchers("/secret.txt").authenticated()//
                .and()//
                // Return 403 accessing resources that require authentication
                .exceptionHandling().authenticationEntryPoint(new Http403ForbiddenEntryPoint()).and()//
                .formLogin().permitAll()//
                // If login fails, return 401
                .failureHandler(new HTTPStatusHandler(HttpStatus.UNAUTHORIZED))//
                // If login succeeds return 200
                .successHandler(new JWTStatusHandler()).and()//
                .logout()//
                // If logout succeeds return 200
                .logoutSuccessHandler(new HTTPStatusHandler(HttpStatus.OK));//
        http.addFilterBefore(new JWTFilter(jwtProvider), UsernamePasswordAuthenticationFilter.class);
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        http.csrf().disable();
    }

    @Bean
    public JWTProvider jwtProvider() {
        return new JWTProvider();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(User.withDefaultPasswordEncoder().username("user").password("123").roles("USER").build());
    }

    class JWTStatusHandler implements AuthenticationSuccessHandler {

        @Override
        public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
                Authentication authentication) throws IOException, ServletException {
            String token = jwtProvider.createToken(authentication.getName());
            response.addHeader("jwt-token", token);
            response.setStatus(HttpStatus.OK.value());

        }

    }

    class HTTPStatusHandler implements AuthenticationFailureHandler, LogoutSuccessHandler {

        private HttpStatus status;

        public HTTPStatusHandler(HttpStatus status) {
            this.status = status;
        }

        @Override
        public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                AuthenticationException exception) throws IOException, ServletException {
            response.setStatus(status.value());
        }

        @Override
        public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response,
                Authentication authentication) throws IOException, ServletException {
            response.setStatus(status.value());
        }

    }
}
