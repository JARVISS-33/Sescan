package com.secscan;

import java.util.List;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ScanRepository extends JpaRepository<ScanEntity, String> {
    List<ScanEntity> findTop20ByOrderByCreatedAtDesc();
}
