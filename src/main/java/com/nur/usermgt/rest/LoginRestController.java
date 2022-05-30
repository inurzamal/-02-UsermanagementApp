package com.nur.usermgt.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nur.usermgt.bindings.LoginForm;
import com.nur.usermgt.services.UserMgmtService;

@RestController
public class LoginRestController {
	
	@Autowired
	private UserMgmtService service;
	
	@PostMapping("/login")
	public String login(@RequestBody LoginForm form) {		
		return service.login(form);
	}

}
