package io.security.corespringsecurity.controller.login;

import org.apache.catalina.security.SecurityUtil;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import io.security.corespringsecurity.domain.Account;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

	@GetMapping("/login")
	public String login(@RequestParam(value = "error", required = false) String error,
		@RequestParam(value = "exception", required = false) String exception, Model model) {

		model.addAttribute("error", error);
		model.addAttribute("exception", exception);

		return "user/login/login";
	}

	@RequestMapping("/api/login")
	@ResponseBody
	public String ajaxLogin(@RequestParam(value = "error", required = false) String error,
		@RequestParam(value = "exception", required = false) String exception, Model model){
		model.addAttribute("error", error);
		model.addAttribute("exception", exception);
		return "login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication != null) {
			new SecurityContextLogoutHandler().logout(request, response, authentication);
		}

		return "redirect:/login";
	}

	@GetMapping("/denied")
	public String accessDenied(@RequestParam(value = "exception", required = false) String exception, Model model) {
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
		Account account = (Account) authentication.getPrincipal();
		model.addAttribute("username", account.getUsername());
		model.addAttribute("exception", exception);

		return "user/login/denied";
	}

}
