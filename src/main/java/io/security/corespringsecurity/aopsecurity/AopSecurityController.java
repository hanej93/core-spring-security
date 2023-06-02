package io.security.corespringsecurity.aopsecurity;

import java.security.Principal;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.security.corespringsecurity.domain.dto.AccountDto;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class AopSecurityController {

	private final AopMethodService aopMethodService;

	@GetMapping("/preAuthorize")
	@PreAuthorize("hasRole('ROLE_USER') and #accountDto.username == principal.name")
	public String preAuthorize(AccountDto accountDto, Model model, Principal principal) {
		model.addAttribute("method", "Success @PreAuthorize");

		return "aop/method";
	}

	@GetMapping("/methodSecured")
	public String methodSecured(Model model){
		aopMethodService.methodSecured();
		model.addAttribute("method", "Success MethodSecured");

		return "aop/method";
	}


}
