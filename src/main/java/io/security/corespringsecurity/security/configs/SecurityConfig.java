package io.security.corespringsecurity.security.configs;

import java.util.Arrays;
import java.util.List;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import lombok.RequiredArgsConstructor;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

	private final AuthenticationConfiguration authenticationConfiguration;

	private final AuthenticationDetailsSource authenticationDetailsSource;
	private final FormAuthenticationSuccessHandler formAuthenticationSuccessHandler;
	private final FormAuthenticationFailureHandler formAuthenticationFailureHandler;

	private final AjaxAuthenticationSuccessHandler ajaxAuthenticationSuccessHandler;
	private final AjaxAuthenticationFailureHandler ajaxAuthenticationFailureHandler;

	private final FormAuthenticationProvider formAuthenticationProvider;
	private final AjaxAuthenticationProvider ajaxAuthenticationProvider;

	@Bean
	AuthenticationManager authenticationManager() throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public WebSecurityCustomizer webSecurityCustomizer() {
		return web -> web.ignoring()
			.requestMatchers(PathRequest.toStaticResources().atCommonLocations());
	}

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.authorizeHttpRequests(authorizationManagerRequestMatcherRegistry -> {
				authorizationManagerRequestMatcherRegistry
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

			.csrf(AbstractHttpConfigurer::disable)

			.authenticationProvider(formAuthenticationProvider)
			.authenticationProvider(ajaxAuthenticationProvider)

			.addFilterBefore(filterSecurityInterceptor(), FilterSecurityInterceptor.class);

		customConfigurer(http);

		return http.build();
	}

	private void customConfigurer(HttpSecurity http) throws Exception {
		http
			.apply(new AjaxLoginConfigurer<>())
			.successHandlerAjax(ajaxAuthenticationSuccessHandler)
			.failureHandlerAjax(ajaxAuthenticationFailureHandler)
			.loginProcessingUrl("/api/login")
			.setAuthenticationManager(authenticationManager());
	}

	public AccessDeniedHandler accessDeniedHandler() {
		FormAccessDeniedHandler formAccessDeniedHandler = new FormAccessDeniedHandler();
		formAccessDeniedHandler.setErrorPage("/denied");
		return formAccessDeniedHandler;
	}

	@Bean
	public FilterSecurityInterceptor filterSecurityInterceptor() throws Exception {
		FilterSecurityInterceptor filterSecurityInterceptor = new FilterSecurityInterceptor();
		filterSecurityInterceptor.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		filterSecurityInterceptor.setAccessDecisionManager(affirmativeBased());
		filterSecurityInterceptor.setAuthenticationManager(authenticationManager());
		return filterSecurityInterceptor;
	}

	private AccessDecisionManager affirmativeBased() {
		return new AffirmativeBased(getAccessDecisionVoters());
	}

	private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
		return Arrays.asList(new RoleVoter());
	}

	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() {
		return new UrlFilterInvocationSecurityMetadataSource();
	}

}
