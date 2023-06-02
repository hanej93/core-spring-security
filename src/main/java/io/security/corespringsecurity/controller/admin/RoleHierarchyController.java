package io.security.corespringsecurity.controller.admin;

import java.util.List;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;
import io.security.corespringsecurity.repository.RoleHierarchyRepository;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class RoleHierarchyController {

	private final RoleHierarchyRepository roleHierarchyRepository;

	@GetMapping(value="/admin/roleHierarchy")
	public String getRoleHierarchy(Model model) throws Exception {

		List<RoleHierarchy> roleHierarchy = roleHierarchyRepository.findAll();
		model.addAttribute("roleHierarchy", roleHierarchy);

		return "admin/roleHierarchy/list";
	}
}
