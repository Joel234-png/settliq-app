#![no_std]

mod test;

use soroban_sdk::{contract, contractimpl, contracttype, Address, Env, Vec};

/// Admin roles. Admin accounts are stored separately from merchant accounts
/// as a deployment convention — the contract itself does not cross-check
/// against a merchant registry, so the separation is upheld by the caller
/// (e.g. the off-chain deployment script) rather than enforced on-chain.
#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum AdminRole {
    Admin,
    SuperAdmin,
}

/// Separately-credentialed admin account, distinct from the merchant entity.
#[contracttype]
#[derive(Clone, Debug)]
pub struct AdminUser {
    pub admin: Address,
    pub role: AdminRole,
    pub active: bool,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    SuperAdmin,
    Admin(Address),
    /// Slot-based index entry: maps a sequential position to an admin address.
    /// Each admin gets its own persistent key so the index never grows in a
    /// single storage entry — no single value inflates with the roster size.
    AdminAt(u32),
    /// Scalar count of how many admin slots have been allocated.
    /// Stored in instance storage as a single small integer.
    AdminCount,
}

#[contracttype]
struct AdminAddedEvent {
    admin: Address,
    role: AdminRole,
}

#[contracttype]
struct AdminRevokedEvent {
    admin: Address,
}

#[contracttype]
struct AdminRoleChangedEvent {
    admin: Address,
    old_role: AdminRole,
    new_role: AdminRole,
}

#[contracttype]
struct SuperAdminTransferredEvent {
    previous: Address,
    new: Address,
}

#[contracttype]
struct AdminDeactivatedEvent {
    admin: Address,
}

#[contracttype]
struct AdminReactivatedEvent {
    admin: Address,
}

#[contract]
pub struct AdminAuthContract;

#[contractimpl]
impl AdminAuthContract {
    /// Bootstrap the store with a single SuperAdmin. All other admin accounts
    /// are created exclusively through `add_admin` (the CLI seed/script path).
    pub fn __constructor(env: Env, super_admin: Address) {
        env.storage().instance().set(&DataKey::SuperAdmin, &super_admin);
        Self::save(
            &env,
            AdminUser {
                admin: super_admin.clone(),
                role: AdminRole::SuperAdmin,
                active: true,
            },
        );
        // Slot 0 holds the super_admin address; count starts at 1.
        env.storage()
            .persistent()
            .set(&DataKey::AdminAt(0), &super_admin);
        env.storage().instance().set(&DataKey::AdminCount, &1u32);
    }

    /// Add an admin to the separate credential store. SuperAdmin only.
    /// If the address is already an admin, its role is updated and a distinct
    /// `AdminRoleChangedEvent` is emitted instead of `AdminAddedEvent`, so
    /// off-chain consumers can distinguish new grants from privilege changes.
    pub fn add_admin(env: Env, caller: Address, admin: Address, role: AdminRole) {
        caller.require_auth();
        Self::require_super_admin(&env, &caller);
        let existing: Option<AdminUser> = env.storage().persistent().get(&DataKey::Admin(admin.clone()));
        let is_new = existing.is_none();
        if let Some(ref old_user) = existing {
            // Role update on an existing admin — emit a distinct event.
            Self::save(
                &env,
                AdminUser {
                    admin: admin.clone(),
                    role: role.clone(),
                    active: old_user.active,
                },
            );
            env.events().publish(
                ("ADMIN_AUTH", "admin_role_changed"),
                AdminRoleChangedEvent {
                    admin,
                    old_role: old_user.role.clone(),
                    new_role: role,
                },
            );
        } else {
            // New admin — write a fresh slot and bump the count.
            Self::save(
                &env,
                AdminUser {
                    admin: admin.clone(),
                    role: role.clone(),
                    active: true,
                },
            );
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::AdminCount)
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::AdminAt(count), &admin.clone());
            env.storage()
                .instance()
                .set(&DataKey::AdminCount, &(count + 1));
            env.events().publish(
                ("ADMIN_AUTH", "admin_added"),
                AdminAddedEvent {
                    admin,
                    role,
                },
            );
        }
        let _ = is_new; // suppress unused warning
    }

    /// Remove an admin from the credential store. SuperAdmin only.
    /// The SuperAdmin cannot revoke their own admin record (fix for #1041).
    pub fn revoke_admin(env: Env, caller: Address, admin: Address) {
        caller.require_auth();
        Self::require_super_admin(&env, &caller);

        // Prevent the SuperAdmin from revoking themselves (#1041)
        let super_admin: Address = env.storage().instance().get(&DataKey::SuperAdmin).unwrap();
        if admin == super_admin {
            panic!("cannot revoke super admin");
        }

        let key = DataKey::Admin(admin.clone());
        if !env.storage().persistent().has(&key) {
            panic!("admin not found");
        }
        env.storage().persistent().remove(&key);

        // Swap-and-shrink: find the slot holding `admin`, replace it with the
        // last slot's address, then remove the last slot and decrement the count.
        // This keeps all slots contiguous without touching unrelated entries.
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AdminCount)
            .unwrap_or(0);
        let mut found_slot: Option<u32> = None;
        for i in 0..count {
            let slot_addr: Address = env
                .storage()
                .persistent()
                .get(&DataKey::AdminAt(i))
                .unwrap();
            if slot_addr == admin {
                found_slot = Some(i);
                break;
            }
        }
        if let Some(slot) = found_slot {
            let last = count - 1;
            if slot != last {
                // Move the last entry into the vacated slot.
                let last_addr: Address = env
                    .storage()
                    .persistent()
                    .get(&DataKey::AdminAt(last))
                    .unwrap();
                env.storage()
                    .persistent()
                    .set(&DataKey::AdminAt(slot), &last_addr);
            }
            env.storage().persistent().remove(&DataKey::AdminAt(last));
            env.storage()
                .instance()
                .set(&DataKey::AdminCount, &last);
        }

        env.events().publish(
            ("ADMIN_AUTH", "admin_revoked"),
            AdminRevokedEvent { admin },
        );
    }

    /// Transfer SuperAdmin rights to a new address. SuperAdmin only (#1042).
    ///
    /// After transfer the previous super admin's record is demoted to
    /// `AdminRole::Admin` so that only the new holder retains SuperAdmin
    /// credentials (#11).
    pub fn transfer_super_admin(env: Env, caller: Address, new_super_admin: Address) {
        caller.require_auth();
        Self::require_super_admin(&env, &caller);

        let previous = caller.clone();

        // Update the SuperAdmin key
        env.storage().instance().set(&DataKey::SuperAdmin, &new_super_admin);

        // Demote the previous super admin to a regular Admin so they no longer
        // hold SuperAdmin credentials (#11).
        Self::save(
            &env,
            AdminUser {
                admin: previous.clone(),
                role: AdminRole::Admin,
                active: true,
            },
        );

        // Ensure the new super admin has an AdminUser record with SuperAdmin role
        let is_new = !env.storage().persistent().has(&DataKey::Admin(new_super_admin.clone()));
        Self::save(
            &env,
            AdminUser {
                admin: new_super_admin.clone(),
                role: AdminRole::SuperAdmin,
                active: true,
            },
        );
        if is_new {
            let count: u32 = env
                .storage()
                .instance()
                .get(&DataKey::AdminCount)
                .unwrap_or(0);
            env.storage()
                .persistent()
                .set(&DataKey::AdminAt(count), &new_super_admin.clone());
            env.storage()
                .instance()
                .set(&DataKey::AdminCount, &(count + 1));
        }

        env.events().publish(
            ("ADMIN_AUTH", "super_admin_transferred"),
            SuperAdminTransferredEvent {
                previous,
                new: new_super_admin,
            },
        );
    }

    /// Deactivate an admin without removing its credential record. SuperAdmin
    /// only. `is_admin` returns false for a deactivated admin.
    ///
    /// The SuperAdmin cannot deactivate themselves: doing so would cause
    /// `authorize(super_admin)` to fail and lock out all SuperAdmin-gated
    /// operations (#12).
    pub fn deactivate_admin(env: Env, caller: Address, admin: Address) {
        caller.require_auth();
        Self::require_super_admin(&env, &caller);

        // Prevent the SuperAdmin from deactivating themselves (#12).
        let super_admin: Address = env.storage().instance().get(&DataKey::SuperAdmin).unwrap();
        if admin == super_admin {
            panic!("cannot deactivate super admin");
        }

        let key = DataKey::Admin(admin.clone());
        let mut user: AdminUser = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic!("admin not found"));

        // Check idempotency: only emit event and persist if actually changing state (#84)
        if !user.active {
            return;
        }

        user.active = false;
        Self::save(&env, user);
        env.events().publish(
            ("ADMIN_AUTH", "admin_deactivated"),
            AdminDeactivatedEvent { admin },
        );
    }

    /// Reactivate a deactivated admin account. SuperAdmin only. (#92)
    pub fn reactivate_admin(env: Env, caller: Address, admin: Address) {
        caller.require_auth();
        Self::require_super_admin(&env, &caller);

        let key = DataKey::Admin(admin.clone());
        let mut user: AdminUser = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_else(|| panic!("admin not found"));

        if user.active {
            panic!("admin is already active");
        }

        user.active = true;
        Self::save(&env, user);
        env.events().publish(
            ("ADMIN_AUTH", "admin_reactivated"),
            AdminReactivatedEvent { admin },
        );
    }

    pub fn get_admin(env: Env, admin: Address) -> Option<AdminUser> {
        env.storage().persistent().get(&DataKey::Admin(admin))
    }

    /// True when the address is an active admin in the store.
    pub fn is_admin(env: Env, admin: Address) -> bool {
        match env.storage().persistent().get::<DataKey, AdminUser>(&DataKey::Admin(admin)) {
            Some(user) => user.active,
            None => false,
        }
    }

    /// Authorization gate for admin-only operations. Rejects any non-admin
    /// address (including merchants), mirroring "require admin JWT on admin routes".
    pub fn authorize(env: Env, caller: Address) {
        caller.require_auth();
        if !Self::is_admin(env.clone(), caller) {
            panic!("unauthorized admin");
        }
    }

    /// Paginated list of current admin addresses (#1044).
    /// Returns up to `page_size` entries starting at `offset`.
    /// Reads are bounded by `page_size`; the full roster is never loaded.
    pub fn list_admins(env: Env, offset: u32, page_size: u32) -> Vec<Address> {
        let count: u32 = env
            .storage()
            .instance()
            .get(&DataKey::AdminCount)
            .unwrap_or(0);
        let start = offset.min(count);
        // Saturate addition to prevent overflow panic (#83)
        let end = start.saturating_add(page_size).min(count);
        let mut page: Vec<Address> = Vec::new(&env);
        for i in start..end {
            if let Some(addr) = env
                .storage()
                .persistent()
                .get::<DataKey, Address>(&DataKey::AdminAt(i))
            {
                page.push_back(addr);
            }
        }
        page
    }

    /// Total number of admin slots currently allocated.
    pub fn admin_count(env: Env) -> u32 {
        env.storage()
            .instance()
            .get(&DataKey::AdminCount)
            .unwrap_or(0)
    }

    fn save(env: &Env, user: AdminUser) {
        // Use persistent() storage so each admin entry has its own TTL (#1043)
        env.storage()
            .persistent()
            .set(&DataKey::Admin(user.admin.clone()), &user);
    }

    fn require_super_admin(env: &Env, caller: &Address) {
        let super_admin: Address = env.storage().instance().get(&DataKey::SuperAdmin).unwrap();
        if caller != &super_admin {
            panic!("not super admin");
        }
    }
}
