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
	private final AopPointcutService aopPointcutService;
	private final AopLiveMethodService aopLiveMethodService;

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

	@GetMapping("/pointcutSecured")
	public String pointcutSecured1(Model model){
		aopPointcutService.notSecured();
		aopPointcutService.pointcutSecured();
		model.addAttribute("method", "Success PointcutSecured");

		return "aop/method";
	}

	@GetMapping("/liveMethodSecured")
	public String liveMethodSecured(Model model){
		aopLiveMethodService.liveMethodSecured();
		model.addAttribute("method", "Success LiveMethodSecured");

		return "aop/method";
	}


}
