package io.security.corespringsecurity.controller.admin;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.security.corespringsecurity.domain.entity.AccessIp;
import io.security.corespringsecurity.repository.AccessIpRepository;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class IpAddressController {

	private final AccessIpRepository accessIpRepository;

	@GetMapping(value="/admin/accessIp")
	public String getIpAddress(Model model) throws Exception {

		List<AccessIp> accessIp = accessIpRepository.findAll();
		model.addAttribute("accessIp", accessIp);

		return "admin/accessIp/list";
	}
}
