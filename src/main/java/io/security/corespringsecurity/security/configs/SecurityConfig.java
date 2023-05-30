package io.security.corespringsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.authentication.AuthenticationManagerFactoryBean;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.CustomAccessDeniedHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final AuthenticationSuccessHandler authenticationSuccessHandler;
	private final AuthenticationFailureHandler authenticationFailureHandler;

	private final UserDetailsService userDetailsService;

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
					.requestMatchers("/api/login").permitAll()
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
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
					.accessDeniedPage("/denied")
					.accessDeniedHandler(accessDeniedHandler());
			});

		http.apply(new CustomSecurityFilterManager());

		return http.build();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		CustomAccessDeniedHandler customAccessDeniedHandler = new CustomAccessDeniedHandler();
		customAccessDeniedHandler.setErrorPage("/denied");

		return customAccessDeniedHandler;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	public class CustomSecurityFilterManager extends AbstractHttpConfigurer<CustomSecurityFilterManager, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);
			http
				.authenticationProvider(new AjaxAuthenticationProvider(passwordEncoder(), userDetailsService))
				.addFilterBefore(new AjaxLoginProcessingFilter(authenticationManager), UsernamePasswordAuthenticationFilter.class)
				.csrf(AbstractHttpConfigurer::disable);

			super.configure(http);
		}
	}

}
