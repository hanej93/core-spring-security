package io.security.corespringsecurity.security.service;

import java.util.Collection;
import java.util.List;

import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;

import io.security.corespringsecurity.domain.entity.Account;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
public class AccountContext extends User {

	private Account account;

	public AccountContext(Account account, List<GrantedAuthority> roles) {
		super(account.getUsername(), account.getPassword(), roles);
		this.account = account;
	}

}
