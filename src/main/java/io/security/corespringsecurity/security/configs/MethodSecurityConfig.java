package io.security.corespringsecurity.security.configs;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.method.MapBasedMethodSecurityMetadataSource;
import org.springframework.security.access.method.MethodSecurityMetadataSource;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.method.configuration.GlobalMethodSecurityConfiguration;

import io.security.corespringsecurity.security.factory.MethodResourcesFactoryBean;
import io.security.corespringsecurity.security.processor.ProtectPointcutPostProcessor;
import io.security.corespringsecurity.service.SecurityResourceService;
import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableGlobalMethodSecurity(securedEnabled = true)
public class MethodSecurityConfig extends GlobalMethodSecurityConfiguration {

	private final SecurityResourceService securityResourceService;

	@Override
	protected MethodSecurityMetadataSource customMethodSecurityMetadataSource() {
		return mapBasedMethodSecurityMetadataSource();
	}

	@Bean
	public MapBasedMethodSecurityMetadataSource mapBasedMethodSecurityMetadataSource() {
		return new MapBasedMethodSecurityMetadataSource(methodResourcesMapFactoryBean().getObject());
	}

	@Bean
	public MethodResourcesFactoryBean methodResourcesMapFactoryBean() {
		MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
		methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesFactoryBean.setResourceType("method");
		return methodResourcesFactoryBean;
	}

	@Bean
	@Profile("pointcut")
	public MethodResourcesFactoryBean pointcutResourcesMapFactoryBean() {
		MethodResourcesFactoryBean methodResourcesFactoryBean = new MethodResourcesFactoryBean();
		methodResourcesFactoryBean.setSecurityResourceService(securityResourceService);
		methodResourcesFactoryBean.setResourceType("pointcut");
		return methodResourcesFactoryBean;
	}

	@Bean
	@Profile("pointcut")
	public ProtectPointcutPostProcessor protectPointcutPostProcessor() {
		ProtectPointcutPostProcessor protectPointcutPostProcessor = new ProtectPointcutPostProcessor(mapBasedMethodSecurityMetadataSource());
		protectPointcutPostProcessor.setPointcutMap(pointcutResourcesMapFactoryBean().getObject());

		return protectPointcutPostProcessor;
	}
}
