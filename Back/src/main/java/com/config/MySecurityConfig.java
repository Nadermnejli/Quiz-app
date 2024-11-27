package com.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@EnableWebSecurity
@Configuration
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class MySecurityConfig extends WebSecurityConfigurerAdapter {

	@Autowired
	private UserDetailsServiceImpl userDetailsServiceImpl;

	@Autowired
	private AuthenticationEntryPoint entryPoint;

	@Autowired
	private JwtAuthenticationFilter filter;

	// Password encoder bean
	@Bean
	public PasswordEncoder passwordEncoder() {
		return new BCryptPasswordEncoder();
	}

	// Authentication manager configuration
	@Override
	protected void configure(AuthenticationManagerBuilder auth) throws Exception {
		auth.userDetailsService(this.userDetailsServiceImpl).passwordEncoder(passwordEncoder());
	}

	@Override
	protected void configure(HttpSecurity http) throws Exception {
		http
				.csrf().disable() // Disabling CSRF for stateless authentication with JWT
				.cors().disable() // Disable CORS if necessary for your setup, else enable it
				.authorizeRequests()
				// Allow Swagger and OpenAPI endpoints without authentication
				.antMatchers("/v3/api-docs/**", "/swagger-ui/**", "/swagger-ui.html", "/swagger-resources/**", "/webjars/**")
				.permitAll()
				// Allow specific endpoints like token creation or user creation
				.antMatchers("/token", "/user/create").permitAll()
				.antMatchers(HttpMethod.OPTIONS).permitAll() // Allow OPTIONS requests for preflight CORS checks
				// All other requests require authentication
				.anyRequest().authenticated()
				.and()
				.exceptionHandling()
				.authenticationEntryPoint(entryPoint) // Your custom authentication entry point
				.and()
				.sessionManagement()
				.sessionCreationPolicy(SessionCreationPolicy.STATELESS); // Stateless session management for JWT

		// Add JWT filter to the security filter chain before the UsernamePasswordAuthenticationFilter
		http.addFilterBefore(filter, UsernamePasswordAuthenticationFilter.class);
	}

	// Expose AuthenticationManager bean
	@Bean
	public AuthenticationManager authenticationManagerBean() throws Exception {
		return super.authenticationManagerBean();
	}
}
