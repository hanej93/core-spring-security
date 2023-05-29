package io.security.corespringsecurity.controller.security.configs;

import org.springframework.boot.autoconfigure.security.servlet.PathRequest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityCustomizer;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

	@Bean
	public UserDetailsService userDetailsService() {

		String password = passwordEncoder().encode("1234");

		UserDetails user = User.builder()
			.username("user")
			.password(password)
			.roles("USER")
			.build();

		UserDetails manager = User.builder()
			.username("manager")
			.password(password)
			.roles("USER", "MANAGER")
			.build();

		UserDetails admin = User.builder()
			.username("admin")
			.password(password)
			.roles("ADMIN", "MANAGER", "USER")
			.build();

		return new InMemoryUserDetailsManager(user, manager, admin);
	}

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
					.requestMatchers("/", "/users").permitAll()
					.requestMatchers("/mypage").hasRole("USER")
					.requestMatchers("/messages").hasRole("MANAGER")
					.requestMatchers("/config").hasRole("ADMIN")
					.anyRequest().authenticated();
			})

			.formLogin(Customizer.withDefaults());

		return http.build();
	}
}
