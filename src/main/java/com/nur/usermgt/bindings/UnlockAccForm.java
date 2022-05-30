package com.nur.usermgt.bindings;

import lombok.Data;

@Data
public class UnlockAccForm {
	
	private String email;
	private String tmpPwd;
	private String newPwd;
	private String confirmNewPwd;
}
