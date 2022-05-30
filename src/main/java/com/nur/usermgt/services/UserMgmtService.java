package com.nur.usermgt.services;

import java.util.Map;

import com.nur.usermgt.bindings.LoginForm;
import com.nur.usermgt.bindings.UnlockAccForm;
import com.nur.usermgt.bindings.UserRegForm;

public interface UserMgmtService {
	
	public String login(LoginForm loginForm);
	
	
	public String emailCheck(String email);
	
	Map<Integer, String> loadCountries();
	
	Map<Integer, String> loadStates(int countryId);
	
	Map<Integer, String> loadCities(int stateId);
	
	public String registerUser(UserRegForm regForm);
	
	
	public String unlockUser(UnlockAccForm unlock);
	
	public String forgotPassword(String email);
	
}
