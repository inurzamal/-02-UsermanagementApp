package com.nur.usermgt.repository;

import java.util.List;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nur.usermgt.entities.CityMasterEntity;

public interface CityRepository extends JpaRepository<CityMasterEntity, Integer> {
	
	public List<CityMasterEntity> findByStateId(Integer stateId);

}
