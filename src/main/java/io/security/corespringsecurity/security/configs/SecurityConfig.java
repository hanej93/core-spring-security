package io.security.corespringsecurity.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import io.security.corespringsecurity.security.filter.AjaxLoginProcessingFilter;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
	private final FormAuthenticationFailureHandler formAuthenticationFailureHandler;

	private final AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler;
	private final AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler;

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
					.successHandler(formAuthenticationSuccessHandler)
					.failureHandler(formAuthenticationFailureHandler)
					.permitAll();
			})

			.exceptionHandling(httpSecurityExceptionHandlingConfigurer -> {
				httpSecurityExceptionHandlingConfigurer
					.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))
					.accessDeniedPage("/denied")
					.accessDeniedHandler(accessDeniedHandler());
			})
			.csrf(AbstractHttpConfigurer::disable);

		http.apply(new AjaxSecurityFilterManager());

		return http.build();
	}

	@Bean
	public AccessDeniedHandler accessDeniedHandler() {
		FormAccessDeniedHandler formAccessDeniedHandler = new FormAccessDeniedHandler();
		formAccessDeniedHandler.setErrorPage("/denied");

		return formAccessDeniedHandler;
	}

	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	public class AjaxSecurityFilterManager extends AbstractHttpConfigurer<AjaxSecurityFilterManager, HttpSecurity> {
		@Override
		public void configure(HttpSecurity http) throws Exception {
			AuthenticationManager authenticationManager = http.getSharedObject(AuthenticationManager.class);

			AjaxLoginProcessingFilter ajaxLoginProcessingFilter = new AjaxLoginProcessingFilter();
			ajaxLoginProcessingFilter.setAuthenticationManager(authenticationManager);
			ajaxLoginProcessingFilter.setAuthenticationSuccessHandler(ajaxAuthenticationSuccessHandler);
			ajaxLoginProcessingFilter.setAuthenticationFailureHandler(ajaxAuthenticationFailureHandler);

			http
				.authenticationProvider(new AjaxAuthenticationProvider(passwordEncoder(), userDetailsService))
				.addFilterBefore(ajaxLoginProcessingFilter, UsernamePasswordAuthenticationFilter.class);

			super.configure(http);
		}
	}

}
