package com.example.dspm.repo;

import com.example.dspm.domain.DataObject;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface DataObjectRepo extends JpaRepository<DataObject, String> {
    Optional<DataObject> findByLocator(String locator);
}
