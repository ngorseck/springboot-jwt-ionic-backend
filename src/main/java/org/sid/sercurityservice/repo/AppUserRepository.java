package org.sid.sercurityservice.repo;

import org.sid.sercurityservice.entities.AppRoles;
import org.sid.sercurityservice.entities.AppUser;
import org.springframework.data.jpa.repository.JpaRepository;

public interface AppUserRepository extends JpaRepository<AppUser, Long> {
    AppUser findByUsername(String username);
}
