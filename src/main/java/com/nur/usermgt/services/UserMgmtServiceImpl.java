package com.nur.usermgt.services;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.BeanUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import com.nur.usermgt.bindings.LoginForm;
import com.nur.usermgt.bindings.UnlockAccForm;
import com.nur.usermgt.bindings.UserRegForm;
import com.nur.usermgt.entities.CityMasterEntity;
import com.nur.usermgt.entities.CountryMasterEntity;
import com.nur.usermgt.entities.StateMasterEntity;
import com.nur.usermgt.entities.UserDtlsEntity;
import com.nur.usermgt.repository.CityRepository;
import com.nur.usermgt.repository.CountryRepository;
import com.nur.usermgt.repository.StateRepository;
import com.nur.usermgt.repository.UserDtlsRepository;
import com.nur.usermgt.utils.EmailUtils;

@Service
public class UserMgmtServiceImpl implements UserMgmtService {

	Logger logger = LoggerFactory.getLogger(UserMgmtServiceImpl.class);

	@Autowired
	private UserDtlsRepository userRepo;

	@Autowired
	private CountryRepository countryRepo;

	@Autowired
	private StateRepository stateRepo;

	@Autowired
	private CityRepository cityRepo;

	@Autowired
	private EmailUtils emailUtils;

	@Override
	public String login(LoginForm loginForm) {

		UserDtlsEntity entity = userRepo.findByEmailAndPassword(loginForm.getEmail(), loginForm.getPwd());

		if (entity == null) {
			return "Inavlid Credentials";
		}

		if ("LOCKED".equals(entity.getAccStatus())) {
			return "Please unlock your account";
		}

		return "Success";
	}

	@Override
	public String emailCheck(String email) {

		UserDtlsEntity entity = userRepo.findByEmail(email);

		if (entity == null) {
			return "Unique Email";
		}
		return "Email ALready exists";
	}

	@Override
	public Map<Integer, String> loadCountries() {

		List<CountryMasterEntity> countries = countryRepo.findAll();

		Map<Integer, String> countryMap = new HashMap<>();

		for (CountryMasterEntity entity : countries) {
			countryMap.put(entity.getCountryId(), entity.getCountryName());
		}

		return countryMap;
	}

	@Override
	public Map<Integer, String> loadStates(int countryId) {

		List<StateMasterEntity> states = stateRepo.findByCountryId(countryId);

		Map<Integer, String> stateMap = new HashMap<>();

		for (StateMasterEntity entity : states) {
			stateMap.put(entity.getStateId(), entity.getStateName());
		}

		return stateMap;
	}

	@Override
	public Map<Integer, String> loadCities(int stateId) {

		List<CityMasterEntity> cities = cityRepo.findByStateId(stateId);

		Map<Integer, String> cityMap = new HashMap<>();

		cities.forEach(entity -> cityMap.put(entity.getCityId(), entity.getCityName()));

		return cityMap;
	}

	@Override
	public String registerUser(UserRegForm regForm) {

		UserDtlsEntity entity = new UserDtlsEntity();
		BeanUtils.copyProperties(regForm, entity);
		entity.setAccStatus("LOCKED");
		entity.setPassword(generateRandomPassword(6));
		UserDtlsEntity savedEntity = userRepo.save(entity);

		String email = regForm.getEmail();
		String subjects = "User Registration - NIELIT Guwahati";
		String fileName = "UNLOCK-ACC-EMAIL-BODY-TEMPLATE.txt";
		String body = readMailBodyContent(fileName, entity);
		boolean isSent = emailUtils.sendEmail(email, subjects, body);

		if (savedEntity.getUserId() != null && isSent) {
			return "SUCCESS";
		}

		return "FAIL";
	}

	@Override
	public String unlockUser(UnlockAccForm unlockAccForm) {

		if (!unlockAccForm.getNewPwd().equals(unlockAccForm.getConfirmNewPwd())) {
			return "Password and Confirm Password should be same";
		}
		UserDtlsEntity entity = userRepo.findByEmailAndPassword(unlockAccForm.getEmail(), unlockAccForm.getTmpPwd());

		if (entity == null) {
			return "Incorrect Email or Temporary Password";
		}
		entity.setPassword(unlockAccForm.getNewPwd());
		entity.setAccStatus("UNLOCKED");
		userRepo.save(entity);

		return "Account Unlocked";
	}

	@Override
	public String forgotPassword(String email) {

		UserDtlsEntity entity = userRepo.findByEmail(email);

		if (entity == null) {
			return "No user available with this email";
		}

		String fileName = "RECOVER-PASSWORD-EMAIL-BODY-TEMPLATE.txt";
		String mailBody = readMailBodyContent(fileName, entity);
		String subjects = "Recover Password";

		boolean isSent = emailUtils.sendEmail(email, subjects, mailBody);

		if (isSent) {
			return "Password Sent to registered Email";
		}

		return null;

	}

	// Generating Random Password

    public static String generateRandomPassword(int len)
    {
        // ASCII range – alphanumeric (0-9, a-z, A-Z)
        final String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
 
        SecureRandom random = new SecureRandom();
        StringBuilder sb = new StringBuilder();
 
        // each iteration of the loop randomly chooses a character from the given
        // ASCII range and appends it to the `StringBuilder` instance
 
        for (int i = 0; i < len; i++)
        {
            int randomIndex = random.nextInt(chars.length());
            sb.append(chars.charAt(randomIndex));
        }
 
        return sb.toString();
    }

	private String readMailBodyContent(String fileName, UserDtlsEntity entity) {

		String mailBody = null;

		StringBuilder sb = new StringBuilder();
		BufferedReader br = null;
		String line = null;

		try {

			br = new BufferedReader(new FileReader(fileName));
			line = br.readLine(); // reading first line data

			while (line != null) {
				sb.append(line); // appending line data to buffer obj
				line = br.readLine(); // reading next line data
			}

			mailBody = sb.toString();

			mailBody = mailBody.replace("{FNAME}", entity.getFname());
			mailBody = mailBody.replace("{LNAME}", entity.getLname());
			mailBody = mailBody.replace("{TEMP-PWD}", entity.getPassword());
			mailBody = mailBody.replace("{EMAIL}", entity.getEmail());
			mailBody = mailBody.replace("{PWD}", entity.getPassword());

		} catch (Exception e) {
			logger.error(e.getMessage(), e);
		}

		finally {
			// this block will be executed in every case, success or caught exception
			if (br != null) {
				// again, a resource is involved, so try-catch another time
				try {
					br.close();
				} catch (IOException e) {
					logger.error(e.getMessage(), e);
				}
			}
		}

		return mailBody;
	}
}
