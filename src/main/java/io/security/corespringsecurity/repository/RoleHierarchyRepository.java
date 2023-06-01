package io.security.corespringsecurity.repository;

import org.springframework.data.jpa.repository.JpaRepository;

import io.security.corespringsecurity.domain.entity.RoleHierarchy;

public interface RoleHierarchyRepository extends JpaRepository<RoleHierarchy, Long> {

    RoleHierarchy findByChildName(String roleName);
}
