package org.sid.sercurityservice.repo;

import org.sid.sercurityservice.entities.AppRoles;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppRoleRepository extends JpaRepository<AppRoles, Long> {
    AppRoles findByRoleName(String roleName);
}
