package com.nur.usermgt.rest;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.nur.usermgt.bindings.UnlockAccForm;
import com.nur.usermgt.services.UserMgmtService;

@RestController
public class UnlockAccRestController {
	
	@Autowired
	private UserMgmtService service;
	
	@PostMapping("/unlock")
	public String unlockAcc(@RequestBody UnlockAccForm form) {	
		return service.unlockUser(form);	
	}
}
