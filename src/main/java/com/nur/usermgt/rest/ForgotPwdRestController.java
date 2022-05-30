package com.nur.usermgt.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.nur.usermgt.services.UserMgmtService;

@RestController
public class ForgotPwdRestController {
	
	@Autowired
	private UserMgmtService service;
	
	@GetMapping("/forgotPwd/{email}")
	public String forgotpwd(@PathVariable String email) {
		return service.forgotPassword(email);
	}

}
