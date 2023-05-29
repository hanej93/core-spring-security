package io.security.corespringsecurity.controller.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import io.security.corespringsecurity.controller.security.handler.CustomAccessDeniedHandler;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final AuthenticationFailureHandler authenticationFailureHandler;

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring()
			.requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return PasswordEncoderFactories.createDelegatingPasswordEncoder();
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
				authorizationManagerRequestMatcherRegistry
					.requestMatchers("/", "/users", "/login").permitAll()
					.requestMatchers("/mypage").hasRole("USER")
					.requestMatchers("/messages").hasRole("MANAGER")
					.requestMatchers("/config").hasRole("ADMIN")
					.anyRequest().authenticated();
			})

			.formLogin(httpSecurityFormLoginConfigurer -> {
				httpSecurityFormLoginConfigurer
					.loginPage("/login")
					.loginProcessingUrl("/login_proc")
					.defaultSuccessUrl("/")
					.authenticationDetailsSource(authenticationDetailsSource)
					.successHandler(authenticationSuccessHandler)
					.failureHandler(authenticationFailureHandler)
					.permitAll();
			})

			.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
				httpSecurityExceptionHandlingConfigurer
					.accessDeniedHandler(accessDeniedHandler());
			});

		return http.build();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
		customAccessDeniedHandler.setErrorPage("/denied");

		return customAccessDeniedHandler;
	}
}
