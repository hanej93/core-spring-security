package io.security.corespringsecurity.security.metadatasource;

import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
public class UrlFilterInvocationSecurityMetadataSource implements FilterInvocationSecurityMetadataSource {

	private final LinkedHashMap<RequestMatcher, List<ConfigAttribute>> requestMap;
	private final SecurityResourceService securityResourceService;

	@Override
	public Collection<ConfigAttribute> getAttributes(Object object) throws IllegalArgumentException {

		HttpServletRequest request = ((FilterInvocation)object).getRequest();

		if (requestMap != null) {
			for (Map.Entry<RequestMatcher, List<ConfigAttribute>> entry : requestMap.entrySet()) {
				RequestMatcher matcher = entry.getKey();
				if (matcher.matches(request)) {
					return entry.getValue();
				}
			}
		}

		return null;
	}

	@Override
	public Collection<ConfigAttribute> getAllConfigAttributes() {
		Set<ConfigAttribute> allAttributes = new HashSet<>();
		this.requestMap.values().forEach(allAttributes::addAll);
		return allAttributes;
	}

	@Override
	public boolean supports(Class<?> clazz) {
		return FilterInvocation.class.isAssignableFrom(clazz);
	}

	public void reload() {
		LinkedHashMap<RequestMatcher, List<ConfigAttribute>> reloadMap = securityResourceService.getResourceList();

		requestMap.clear();

		reloadMap.entrySet().forEach(entry -> {
			requestMap.put(entry.getKey(), entry.getValue());
		});
	}

}
