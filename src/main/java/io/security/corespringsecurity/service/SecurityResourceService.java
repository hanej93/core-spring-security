package io.security.corespringsecurity.service;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;
import org.springframework.stereotype.Service;

import io.security.corespringsecurity.domain.entity.Resources;
import io.security.corespringsecurity.repository.ResourcesRepository;
import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class SecurityResourceService {

	private final ResourcesRepository resourcesRepository;

	public LinkedHashMap<RequestMatcher, List<ConfigAttribute>> getResourceList() {
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> result = new LinkedHashMap<>();
		List<Resources> resources = resourcesRepository.findAllResources();
		resources.forEach(resource -> {
			List<ConfigAttribute> configAttributes = new ArrayList<>();
			resource.getRoleSet().forEach(role -> {
				configAttributes.add(new SecurityConfig(role.getRoleName()));
			});
			result.put(new AntPathRequestMatcher(resource.getResourceName()), configAttributes);
		});

		return result;
	}
}
