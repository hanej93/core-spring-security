package io.security.corespringsecurity.security.service;

import java.util.List;
import java.util.stream.Collectors;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.entity.Account;
import io.security.corespringsecurity.repository.UserRepository;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class UserDetailsServiceImpl implements UserDetailsService {

	private final UserRepository userRepository;
	private final HttpServletRequest request;

	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

		Account account = userRepository.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("No user found with username: " + username));

		List<GrantedAuthority> collect = account.getUserRoles()
			.stream()
			.map(userRole -> userRole.getRoleName())
			.collect(Collectors.toSet())
			.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

		//List<GrantedAuthority> collect = userRoles.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());
		return new AccountContext(account, collect);
	}

}
