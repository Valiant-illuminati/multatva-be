package com.ekart.multatva.repository;

import com.ekart.multatva.entity.RoleEntity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface RoleRepository extends JpaRepository<RoleEntity, Long> {
        Optional<RoleEntity> findByName(String name);
    }

