package com.nur.usermgt.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import com.nur.usermgt.entities.CountryMasterEntity;

public interface CountryRepository extends JpaRepository<CountryMasterEntity, Integer> {

}
