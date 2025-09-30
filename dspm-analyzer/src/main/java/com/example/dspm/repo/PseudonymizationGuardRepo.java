package com.example.dspm.repo;

import com.example.dspm.domain.PseudonymizationGuard;
import org.springframework.data.domain.Pageable;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;

public interface PseudonymizationGuardRepo extends JpaRepository<PseudonymizationGuard, String> {

    @Query("""
      select o.locator, g from com.example.dspm.domain.PseudonymizationGuard g
      join com.example.dspm.domain.DataObject o on o.id = g.objectId
      where g.isPseudonymized = true and coalesce(g.separated,false) = false
      order by g.checkedAt desc
    """)
    List<Object[]> findViolationsPaged(Pageable pageable);

    @Query("select count(g) from com.example.dspm.domain.PseudonymizationGuard g where g.isPseudonymized = true")
    long countTotal();

    @Query("select count(g) from com.example.dspm.domain.PseudonymizationGuard g where g.isPseudonymized = true and coalesce(g.separated,false) = true")
    long countOk();
}
