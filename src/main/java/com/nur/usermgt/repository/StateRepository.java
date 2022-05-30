package com.nur.usermgt.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nur.usermgt.entities.StateMasterEntity;

public interface StateRepository extends JpaRepository<StateMasterEntity, Integer> {
	
	public List<StateMasterEntity> findByCountryId(Integer countryId);

}
