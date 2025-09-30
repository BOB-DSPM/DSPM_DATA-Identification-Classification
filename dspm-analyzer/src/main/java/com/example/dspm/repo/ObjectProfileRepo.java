package com.example.dspm.repo;

import com.example.dspm.domain.ObjectProfile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.Optional;

public interface ObjectProfileRepo extends JpaRepository<ObjectProfile, String> {

    @Query("""
      select p from ObjectProfile p join com.example.dspm.domain.DataObject o on o.id = p.objectId
      where o.locator = :locator
    """)
    Optional<ObjectProfile> findByLocator(String locator);
}
