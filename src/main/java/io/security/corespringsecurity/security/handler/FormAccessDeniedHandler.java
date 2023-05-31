package io.security.corespringsecurity.security.handler;

import java.io.IOException;
import java.net.URLEncoder;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.RedirectStrategy;
import org.springframework.security.web.access.AccessDeniedHandler;

import com.fasterxml.jackson.databind.ObjectMapper;

import io.security.corespringsecurity.util.WebUtil;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class FormAccessDeniedHandler implements AccessDeniedHandler {

	private String errorPage;
	private ObjectMapper mapper = new ObjectMapper();
	private RedirectStrategy redirectStrategy = new DefaultRedirectStrategy();

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		if (WebUtil.isAjax(request)) {
			response.setContentType(MediaType.APPLICATION_JSON_VALUE);
			response.getWriter().write(this.mapper.writeValueAsString(ResponseEntity.status(HttpStatus.FORBIDDEN)));
		} else {
			String deniedUrl = errorPage + "?exception=" + URLEncoder.encode(accessDeniedException.getMessage(), "UTF-8");
			redirectStrategy.sendRedirect(request, response, deniedUrl);
		}
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}
}
