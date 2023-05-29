package io.security.corespringsecurity.controller.security.service;

import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.Account;
import io.security.corespringsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

	private final UserRepository userRepository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		Account account = userRepository.findByUsername(username)
			.orElseThrow(() -> new UsernameNotFoundException("UsernameNotFoundException"));

		List<GrantedAuthority> roles = AuthorityUtils.createAuthorityList(account.getRole());

		AccountContext accountContext = new AccountContext(account, roles);

		return accountContext;
	}

}
