package io.security.corespringsecurity.controller.security.handler;

import java.io.IOException;

import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.stereotype.Component;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

	private String errorPage;

	@Override
	public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
		String deniedUrl = errorPage + "?exception=" + accessDeniedException.getMessage();
		response.sendRedirect(deniedUrl);
	}

	public void setErrorPage(String errorPage) {
		this.errorPage = errorPage;
	}
}
