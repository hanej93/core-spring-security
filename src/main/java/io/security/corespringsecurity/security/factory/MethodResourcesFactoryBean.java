package io.security.corespringsecurity.security.factory;

import java.util.LinkedHashMap;
import java.util.List;

import org.springframework.beans.factory.FactoryBean;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.web.util.matcher.RequestMatcher;

import io.security.corespringsecurity.service.SecurityResourceService;

public class MethodResourcesFactoryBean implements FactoryBean<LinkedHashMap<String, List<ConfigAttribute>>> {

	private SecurityResourceService securityResourceService;
	private String resourceType;
	private LinkedHashMap<String, List<ConfigAttribute>> resourceMap;

	public void setSecurityResourceService(SecurityResourceService securityResourceService) {
		this.securityResourceService = securityResourceService;
	}

	public void setResourceType(String resourceType) {
		this.resourceType = resourceType;
	}

	@Override
	public LinkedHashMap<String, List<ConfigAttribute>> getObject(){
		if (resourceMap == null) {
			init();
		}

		return resourceMap;
	}

	private void init() {
		if ("method".equals(resourceType)) {
			resourceMap = securityResourceService.getMethodResourceList();
		} else if ("pointcut".equals(resourceType)) {
			resourceMap = securityResourceService.getPointcutResourceList();
		}
	}

	@Override
	public Class<?> getObjectType() {
		return LinkedHashMap.class;
	}

	@Override
	public boolean isSingleton() {
		return true;
	}
}
