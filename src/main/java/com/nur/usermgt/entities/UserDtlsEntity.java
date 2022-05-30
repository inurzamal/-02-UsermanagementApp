package com.nur.usermgt.entities;

import java.time.LocalDate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.persistence.Table;

import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;
import lombok.Data;

@Entity
@Table(name="USER_DTLS")
@Data
public class UserDtlsEntity {
	
	@Id
	@GeneratedValue
	private Long userId;
	
	private String fname;
	
	private String lname;
	
	@Column(unique=true)
	private String email;
	
	private String password;
	
	private Long phno;
	
	private LocalDate dob;
	
	private String gender;
	
	@Column(name="CITY_ID")
	private Integer cityId;
	
	@Column(name="STATE_ID")
	private Integer stateId;
	
	@Column(name="COUNTRY_ID")
	private Integer countryId;
	
	private String accStatus;
	
	@Column(name="CREATED_DATE", updatable=false)
	@CreationTimestamp
	private LocalDate createdDate;
	
	@Column(name="UPDATED_DATE", insertable=false)
	@UpdateTimestamp
	private LocalDate updatedDate;

}
