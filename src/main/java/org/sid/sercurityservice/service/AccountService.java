package org.sid.sercurityservice.service;

import org.sid.sercurityservice.entities.AppRoles;
import org.sid.sercurityservice.entities.AppUser;

import java.util.List;

public interface AccountService {
    AppUser addNewUser(AppUser appUser);
    AppRoles addNewRole(AppRoles appRoles);
    void addRoleToUser(String username, String roleName);
    AppUser loadUserByUsername(String username);
    List<AppUser> listUsers();
}
