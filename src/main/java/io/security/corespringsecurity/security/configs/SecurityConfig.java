package io.security.corespringsecurity.security.configs;

import java.util.ArrayList;
import java.util.List;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDecisionVoter;
import org.springframework.security.access.hierarchicalroles.RoleHierarchyImpl;
import org.springframework.security.access.vote.AffirmativeBased;
import org.springframework.security.access.vote.RoleHierarchyVoter;
import org.springframework.security.authentication.AuthenticationDetailsSource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import io.security.corespringsecurity.security.factory.UrlResourcesMapFactoryBean;
import io.security.corespringsecurity.security.filter.PermitAllFilter;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.AjaxAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.handler.FormAccessDeniedHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationFailureHandler;
import io.security.corespringsecurity.security.handler.FormAuthenticationSuccessHandler;
import io.security.corespringsecurity.security.metadatasource.UrlFilterInvocationSecurityMetadataSource;
import io.security.corespringsecurity.security.provider.AjaxAuthenticationProvider;
import io.security.corespringsecurity.security.provider.FormAuthenticationProvider;
import io.security.corespringsecurity.service.SecurityResourceService;
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

	private final FormAuthenticationProvider formAuthenticationProvider;
	private final AjaxAuthenticationProvider ajaxAuthenticationProvider;

	private final SecurityResourceService securityResourceService;

	private String[] permitAllPattern = {"/", "/login", "/user/login/**"};

	@Bean
	AuthenticationManager authenticationManager(HttpSecurity http) throws Exception {
		AuthenticationManagerBuilder authenticationManagerBuilder = http.getSharedObject(AuthenticationManagerBuilder.class);
		authenticationManagerBuilder.authenticationProvider(formAuthenticationProvider);
		authenticationManagerBuilder.authenticationProvider(ajaxAuthenticationProvider);
		return authenticationManagerBuilder.build();
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
					.anyRequest().permitAll();
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

			.addFilterBefore(filterSecurityInterceptor(http), FilterSecurityInterceptor.class);

		customConfigurer(http);

		return http.build();
	}

	private void customConfigurer(HttpSecurity http) throws Exception {
		http
			.apply(new AjaxLoginConfigurer<>())
			.successHandlerAjax(ajaxAuthenticationSuccessHandler)
			.failureHandlerAjax(ajaxAuthenticationFailureHandler)
			.loginProcessingUrl("/api/login")
			.setAuthenticationManager(authenticationManager(http));
	}

	public AccessDeniedHandler accessDeniedHandler() {
		FormAccessDeniedHandler formAccessDeniedHandler = new FormAccessDeniedHandler();
		formAccessDeniedHandler.setErrorPage("/denied");
		return formAccessDeniedHandler;
	}

	@Bean
	public PermitAllFilter filterSecurityInterceptor(HttpSecurity http) throws Exception {
		PermitAllFilter permitAllFilter = new PermitAllFilter(permitAllPattern);
		permitAllFilter.setSecurityMetadataSource(urlFilterInvocationSecurityMetadataSource());
		permitAllFilter.setAccessDecisionManager(affirmativeBased());
		permitAllFilter.setAuthenticationManager(authenticationManager(http));
		return permitAllFilter;
	}

	private AccessDecisionManager affirmativeBased() {
		return new AffirmativeBased(getAccessDecisionVoters());
	}

	private List<AccessDecisionVoter<?>> getAccessDecisionVoters() {
		List<AccessDecisionVoter<? extends Object>> accessDecisionVoters = new ArrayList<>();
		accessDecisionVoters.add(roleVoter());
		return accessDecisionVoters;
	}

	@Bean
	public AccessDecisionVoter<? extends Object> roleVoter() {
		return new RoleHierarchyVoter(roleHierarchy());
	}

	@Bean
	public RoleHierarchyImpl roleHierarchy() {
		return new RoleHierarchyImpl();
	}

	@Bean
	public FilterInvocationSecurityMetadataSource urlFilterInvocationSecurityMetadataSource() throws Exception {
		return new UrlFilterInvocationSecurityMetadataSource(urlResourcesMapFactoryBean().getObject(), securityResourceService);
	}

	private UrlResourcesMapFactoryBean urlResourcesMapFactoryBean() {
		UrlResourcesMapFactoryBean urlResourcesMapFactoryBean = new UrlResourcesMapFactoryBean();
		urlResourcesMapFactoryBean.setSecurityResourceService(securityResourceService);
		return urlResourcesMapFactoryBean;
	}

}
