package io.security.corespringsecurity.security.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;

public class PermitAllFilter extends FilterSecurityInterceptor {

	private static final String FILTER_APPLIED = "__spring_security_filterSecurityInterceptor_filterApplied";

	private List<RequestMatcher> permitAllRequestMatcher = new ArrayList<>();

	public PermitAllFilter(String... permitAllPattern) {
		createPermitAllPattern(permitAllPattern);
	}

	@Override
	protected InterceptorStatusToken beforeInvocation(Object object) {
		HttpServletRequest request = ((FilterInvocation) object).getRequest();

		boolean permitAll = permitAllRequestMatcher.stream()
			.filter(matcher -> matcher.matches(request))
			.findAny()
			.isPresent();

		if (permitAll) {
			return null;
		}

		return super.beforeInvocation(object);
	}

	@Override
	public void invoke(FilterInvocation fi) throws IOException, ServletException {

		if ((fi.getRequest() != null) && (fi.getRequest().getAttribute(FILTER_APPLIED) != null)
			&& super.isObserveOncePerRequest()) {
			// filter already applied to this request and user wants us to observe
			// once-per-request handling, so don't re-do security checking
			fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
		} else {
			// first time this request being called, so perform security checking
			if (fi.getRequest() != null) {
				fi.getRequest().setAttribute(FILTER_APPLIED, Boolean.TRUE);
			}

			InterceptorStatusToken token = beforeInvocation(fi);

			try {
				fi.getChain().doFilter(fi.getRequest(), fi.getResponse());
			} finally {
				super.finallyInvocation(token);
			}

			super.afterInvocation(token, null);
		}
	}

	private void createPermitAllPattern(String... permitAllPattern) {
		for (String pattern : permitAllPattern) {
			permitAllRequestMatcher.add(new AntPathRequestMatcher(pattern));
		}
	}

}
