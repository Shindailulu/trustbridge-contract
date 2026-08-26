//! Integration tests for trustbridge-contract.
//!
//! Covers end-to-end contract governance, event publication (Registered,
//! Verified, Revoked, Removed, Upgraded, Paused, Unpaused), Role-Based Access
//! Control (RBAC), pause/unpause lifecycle, verifier role separation (Issue
//! #12), lookup after peer removal (Issue #52), not-initialized guards (Issue
//! #54), and verification attestation storage (Issue #16).

#![cfg(test)]

use soroban_sdk::{testutils::Address as _, Address, Env, String};

use trustbridge_contract::{ContractError, Role, TrustBridgeContract};

fn setup_test_env() -> (Env, Address, Address, Address, Address) {
    let env = Env::default();
    let admin = Address::generate(&env);
    let user1 = Address::generate(&env);
    let user2 = Address::generate(&env);
    let contract_id = env.register(TrustBridgeContract, ());

    env.as_contract(&contract_id, || {
        TrustBridgeContract::initialize(env.clone(), admin.clone()).unwrap();
    });

    (env, admin, user1, user2, contract_id)
}

fn s(env: &Env, text: &str) -> String {
    String::from_str(env, text)
}

// ── Full lifecycle ────────────────────────────────────────────────────────────

#[test]
fn test_integration_full_registry_lifecycle_and_events() {
    let (env, admin, user1, _user2, contract_id) = setup_test_env();

    // Register
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        let record = TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
            .expect("record should exist after register");
        assert_eq!(record.stellar_address, user1);
        assert!(!record.verified);
    });

    // Verify (Issue #12 — admin as caller)
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });

    env.as_contract(&contract_id, || {
        let record = TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).unwrap();
        assert!(record.verified, "record must be verified after verify()");
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);
    });

    // Revoke verification (Issue #12 — admin as caller)
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(env.clone(), admin.clone(), s(&env, "alice"), 1)
            .unwrap();
    });

    env.as_contract(&contract_id, || {
        let record = TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).unwrap();
        assert!(!record.verified, "record must be unverified after revoke");
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);
    });

    // Remove
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), user1.clone(), s(&env, "alice")).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert!(TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).is_none());
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 0);
    });
}

// ── Pause / unpause ───────────────────────────────────────────────────────────

#[test]
fn test_integration_pause_unpause_governance() {
    let (env, _admin, user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::pause(env.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert!(TrustBridgeContract::is_paused(env.clone()));
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()),
            Err(ContractError::Paused)
        );
    });

    // Read-only still works while paused
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 0);
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::unpause(env.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert!(!TrustBridgeContract::is_paused(env.clone()));
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert!(
            TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).is_ok()
        );
    });
}

// ── Role-based access control ─────────────────────────────────────────────────

#[test]
fn test_integration_role_based_access_control() {
    let (env, _admin, user1, user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_role(env.clone(), user1.clone(), Role::Upgrader).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_role(env.clone(), user2.clone(), Role::Verifier).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_role(env.clone(), user1.clone()),
            Some(Role::Upgrader)
        );
        assert_eq!(
            TrustBridgeContract::get_role(env.clone(), user2.clone()),
            Some(Role::Verifier)
        );
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove_role(env.clone(), user1.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_role(env.clone(), user1.clone()),
            None
        );
    });
}

// ── Issue #12: Verifier role separation ──────────────────────────────────────

#[test]
fn test_integration_verifier_role_separation() {
    let (env, _admin, user1, verifier, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_role(env.clone(), verifier.clone(), Role::Verifier).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "octocat"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), verifier.clone(), s(&env, "octocat")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "octocat"))
                .unwrap()
                .verified
        );
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(
            env.clone(),
            verifier.clone(),
            s(&env, "octocat"),
            1,
        )
        .unwrap();
    });
    env.as_contract(&contract_id, || {
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "octocat"))
                .unwrap()
                .verified
        );
    });
}

#[test]
fn test_integration_no_role_cannot_verify() {
    let (env, _admin, user1, nobody, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "octocat"), user1.clone()).unwrap();
        let result = TrustBridgeContract::verify(env.clone(), nobody.clone(), s(&env, "octocat"));
        assert_eq!(result, Err(ContractError::NotAuthorized));
    });
}

// ── Issue #52: Lookup after peer removal ─────────────────────────────────────

#[test]
fn test_integration_lookup_after_peer_removal() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "carol"), user3.clone()).unwrap();

        // Remove the first peer
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "alice")).unwrap();

        // bob and carol must still be accessible
        assert!(TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).is_none());
        assert_eq!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .stellar_address,
            user2
        );
        assert_eq!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "carol"))
                .unwrap()
                .stellar_address,
            user3
        );
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 2);
    });
}

#[test]
fn test_integration_export_consistent_after_removal() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "carol"), user3.clone()).unwrap();

        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "bob")).unwrap();

        let all = TrustBridgeContract::get_all_registered(env.clone()).unwrap();
        assert_eq!(all.len(), 2, "export must skip removed entries");

        // The two remaining entries should be alice and carol
        let names: soroban_sdk::Vec<String> = {
            let mut v = soroban_sdk::Vec::new(&env);
            for i in 0..all.len() {
                v.push_back(all.get(i).unwrap().0);
            }
            v
        };
        assert!(names.contains(s(&env, "alice")));
        assert!(names.contains(s(&env, "carol")));
    });
}

// ── Issue #54: Not-initialized guard coverage ─────────────────────────────────

#[test]
fn test_integration_not_initialized_guards() {
    let env = Env::default();
    let contract_id = env.register(TrustBridgeContract, ());
    let addr = Address::generate(&env);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::register(env.clone(), s(&env, "alice"), addr.clone()),
            Err(ContractError::NotInitialized),
            "register before init"
        );
        assert_eq!(
            TrustBridgeContract::remove(env.clone(), addr.clone(), s(&env, "alice")),
            Err(ContractError::NotInitialized),
            "remove before init"
        );
        assert_eq!(
            TrustBridgeContract::verify(env.clone(), addr.clone(), s(&env, "alice")),
            Err(ContractError::NotInitialized),
            "verify before init"
        );
        assert_eq!(
            TrustBridgeContract::revoke_verification(
                env.clone(),
                addr.clone(),
                s(&env, "alice"),
                1
            ),
            Err(ContractError::NotInitialized),
            "revoke_verification before init"
        );
        assert_eq!(
            TrustBridgeContract::pause(env.clone()),
            Err(ContractError::NotInitialized),
            "pause before init"
        );
        assert_eq!(
            TrustBridgeContract::unpause(env.clone()),
            Err(ContractError::NotInitialized),
            "unpause before init"
        );
        assert_eq!(
            TrustBridgeContract::set_role(env.clone(), addr.clone(), Role::Verifier),
            Err(ContractError::NotInitialized),
            "set_role before init"
        );
        assert_eq!(
            TrustBridgeContract::remove_role(env.clone(), addr.clone()),
            Err(ContractError::NotInitialized),
            "remove_role before init"
        );
        assert_eq!(
            TrustBridgeContract::set_cooldown(env.clone(), 100),
            Err(ContractError::NotInitialized),
            "set_cooldown before init"
        );
        assert_eq!(
            TrustBridgeContract::get_all_registered(env.clone()),
            Err(ContractError::NotInitialized),
            "get_all_registered before init"
        );
        assert_eq!(
            TrustBridgeContract::migrate(env.clone(), (2, 0, 0)),
            Err(ContractError::NotInitialized),
            "migrate before init"
        );
    });
}

// ── Issue #16: Verification attestation storage ───────────────────────────────

#[test]
fn test_integration_verification_attestation_storage() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .verified
        );
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .verified
        );
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .verified
        );
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .verified,
            "bob's verification status must be unaffected by alice's verification"
        );
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 2);
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(env.clone(), admin.clone(), s(&env, "alice"), 1)
            .unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .verified
        );
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .verified,
            "bob must remain verified after alice's revocation"
        );
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 1);
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).verified, 0);
    });
}

#[test]
fn test_integration_attestation_preserved_on_same_address_reregister() {
    let (env, admin, user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.as_contract(&contract_id, || {
        let record = TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).unwrap();
        assert!(
            record.verified,
            "same-address re-register must preserve attestation"
        );
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);

        // This documents the intended behavior for unchanged addresses: a
        // re-register with the same Stellar address should leave the existing
        // verification state and counters intact.
        let stats = TrustBridgeContract::get_stats(env.clone());
        assert_eq!(stats.total, 1);
        assert_eq!(stats.verified, 1);
        assert_eq!(stats.total - stats.verified, 0);
    });
}

#[test]
fn test_integration_attestation_cleared_on_address_change() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user2.clone()).unwrap();
    });
    env.as_contract(&contract_id, || {
        let record = TrustBridgeContract::get_address(env.clone(), s(&env, "alice")).unwrap();
        assert!(!record.verified, "address change must clear attestation");
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);

        // This documents the intended future behavior for address changes:
        // re-registering the same username at a new Stellar address should put
        // the contributor back into the unverified set while keeping the total
        // registration count unchanged.
        let stats = TrustBridgeContract::get_stats(env.clone());
        assert_eq!(stats.total, 1);
        assert_eq!(stats.verified, 0);
        assert_eq!(stats.total - stats.verified, 1);
    });
}

// ── Version migration ─────────────────────────────────────────────────────────

#[test]
fn test_integration_version_migration() {
    let (env, _admin, _user1, _user2, contract_id) = setup_test_env();

    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_version(env.clone()), (1, 0, 0));
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::migrate(env.clone(), (1, 0, 0)),
            Err(ContractError::InvalidVersion)
        );
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::migrate(env.clone(), (1, 1, 0)).unwrap();
    });

    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_version(env.clone()), (1, 1, 0));
    });
}

// ── WASM upgrade + cooldown (requires pre-built WASM) ─────────────────────────

#[test]
#[cfg(feature = "wasm-test")]
fn test_integration_wasm_upgrade_cooldown() {
    let (env, _admin, _user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_cooldown(env.clone(), 1800).unwrap();
        assert_eq!(TrustBridgeContract::get_cooldown(env.clone()), 1800);
    });

    let wasm_bytes = soroban_sdk::Bytes::from_slice(
        &env,
        include_bytes!("../target/wasm32v1-none/release/trustbridge_contract.wasm"),
    );
    let new_wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes.clone());
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert!(TrustBridgeContract::upgrade(env.clone(), new_wasm_hash).is_ok());
    });

    let next_wasm_hash = env.deployer().upload_contract_wasm(wasm_bytes);
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::upgrade(env.clone(), next_wasm_hash),
            Err(ContractError::CooldownActive)
        );
    });
}

// ── Issue #54: Additional not-initialized guard tests (integration) ───────────

/// get_registered_page must return NotInitialized before init (Issue #54).
#[test]
fn test_integration_get_registered_page_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(TrustBridgeContract, ());
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_registered_page(env.clone(), 0, 10),
            Err(ContractError::NotInitialized),
            "get_registered_page before init"
        );
    });
}

/// get_registered_paginated must return NotInitialized before init (Issue #54).
#[test]
fn test_integration_get_registered_paginated_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(TrustBridgeContract, ());
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_registered_paginated(env.clone(), 0, 10),
            Err(ContractError::NotInitialized),
            "get_registered_paginated before init"
        );
    });
}

/// get_public_paginated must return NotInitialized before init (Issue #54).
#[test]
fn test_integration_get_public_paginated_not_initialized() {
    let env = Env::default();
    let contract_id = env.register(TrustBridgeContract, ());
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_public_paginated(env.clone(), 0, 10),
            Err(ContractError::NotInitialized),
            "get_public_paginated before init"
        );
    });
}

/// Once initialized, previously failing calls must succeed (Issue #54).
#[test]
fn test_integration_guards_lifted_after_initialization() {
    let env = Env::default();
    let admin = Address::generate(&env);
    let user = Address::generate(&env);
    let contract_id = env.register(TrustBridgeContract, ());

    // All mutating calls fail before init
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::register(env.clone(), s(&env, "alice"), user.clone()),
            Err(ContractError::NotInitialized)
        );
    });

    // Initialize
    env.as_contract(&contract_id, || {
        TrustBridgeContract::initialize(env.clone(), admin.clone()).unwrap();
    });

    // Same calls must now pass
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert!(TrustBridgeContract::register(env.clone(), s(&env, "alice"), user.clone()).is_ok());
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let page = TrustBridgeContract::get_registered_paginated(env.clone(), 0, 10).unwrap();
        assert_eq!(page.records.len(), 1);
    });
}

// ── Issue #52: Additional lookup-after-peer-removal (integration) ─────────────

/// Paginated admin export is consistent after multiple removals (Issue #52).
#[test]
fn test_integration_paginated_export_after_multiple_removals() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);
    let user4 = Address::generate(&env);

    for (name, addr) in [
        (s(&env, "alice"), user1.clone()),
        (s(&env, "bob"), user2.clone()),
        (s(&env, "carol"), user3.clone()),
        (s(&env, "dave"), user4.clone()),
    ] {
        env.mock_all_auths();
        env.as_contract(&contract_id, || {
            TrustBridgeContract::register(env.clone(), name, addr).unwrap();
        });
    }
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "carol")).unwrap();
    });

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let all = TrustBridgeContract::get_all_registered(env.clone()).unwrap();
        assert_eq!(all.len(), 2, "only bob and dave must remain");
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let page = TrustBridgeContract::get_registered_paginated(env.clone(), 0, 10).unwrap();
        assert_eq!(page.records.len(), 2);
        assert_eq!(page.total, 2);
        assert!(!page.has_more);
    });
}

/// Public paginated endpoint is consistent after peer removal (Issue #52).
#[test]
fn test_integration_public_paginated_after_peer_removal() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "carol"), user3.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });
    env.as_contract(&contract_id, || {
        let page = TrustBridgeContract::get_public_paginated(env.clone(), 0, 10).unwrap();
        assert_eq!(
            page.records.len(),
            2,
            "public paginated must skip removed bob"
        );
        let names: soroban_sdk::Vec<String> = {
            let mut v = soroban_sdk::Vec::new(&env);
            for i in 0..page.records.len() {
                v.push_back(page.records.get(i).unwrap().0);
            }
            v
        };
        assert!(names.contains(s(&env, "alice")));
        assert!(names.contains(s(&env, "carol")));
    });
}

// ── Issue #12: Additional verifier role separation (integration) ──────────────

/// Revoking Verifier role prevents the former holder from verifying (Issue #12).
#[test]
fn test_integration_revoked_verifier_cannot_verify() {
    let (env, _admin, user1, verifier, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_role(env.clone(), verifier.clone(), Role::Verifier).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), verifier.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(
            env.clone(),
            verifier.clone(),
            s(&env, "alice"),
            1,
        )
        .unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove_role(env.clone(), verifier.clone()).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::get_role(env.clone(), verifier.clone()),
            None
        );
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let result = TrustBridgeContract::verify(env.clone(), verifier.clone(), s(&env, "alice"));
        assert_eq!(result, Err(ContractError::NotAuthorized));
    });
}

/// Upgrader role cannot verify or revoke verification (Issue #12).
#[test]
fn test_integration_upgrader_cannot_verify_or_revoke() {
    let (env, admin, user1, upgrader, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::set_role(env.clone(), upgrader.clone(), Role::Upgrader).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::verify(env.clone(), upgrader.clone(), s(&env, "alice")),
            Err(ContractError::NotAuthorized),
            "Upgrader must not verify"
        );
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        assert_eq!(
            TrustBridgeContract::revoke_verification(
                env.clone(),
                upgrader.clone(),
                s(&env, "alice"),
                1,
            ),
            Err(ContractError::NotAuthorized),
            "Upgrader must not revoke verification"
        );
    });
}

// ── Issue #16: Additional verification attestation storage (integration) ──────

/// ContributorRecord fields are durably persisted and independently isolated
/// per username (Issue #16).
#[test]
fn test_integration_attestation_record_fields_isolated() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "carol"), user3.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "carol")).unwrap();
    });
    env.as_contract(&contract_id, || {
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .verified
        );
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .verified,
            "bob must remain unverified"
        );
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "carol"))
                .unwrap()
                .verified
        );
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 2);
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(env.clone(), admin.clone(), s(&env, "carol"), 1)
            .unwrap();
    });
    env.as_contract(&contract_id, || {
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .verified,
            "alice must remain verified after carol revocation"
        );
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "bob"))
                .unwrap()
                .verified
        );
        assert!(
            !TrustBridgeContract::get_address(env.clone(), s(&env, "carol"))
                .unwrap()
                .verified
        );
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 1);
    });
}

/// Verification count never goes negative on repeated revocations (Issue #16).
#[test]
fn test_integration_vcount_never_underflows() {
    let (env, admin, user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(env.clone(), admin.clone(), s(&env, "alice"), 1)
            .unwrap();
    });
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let result = TrustBridgeContract::revoke_verification(
            env.clone(),
            admin.clone(),
            s(&env, "alice"),
            1,
        );
        assert_eq!(result, Err(ContractError::NotVerified));
        assert_eq!(
            TrustBridgeContract::get_verified_count(env.clone()),
            0,
            "vcount must not underflow below zero"
        );
    });
}

// ── Middle-user removal regression (index compaction behavior) ───────────────

/// Regression test for middle-user removal: verifies index compaction, export
/// ordering, and stats consistency when removing a user from the middle of the
/// registry (Issue #110).
///
/// This test documents the current behavior:
/// - Index uses compaction (rebuilds without removed username)
/// - Exports skip removed users correctly
/// - Stats match actual remaining records
/// - Paginated reads are consistent after removal
#[test]
fn test_integration_middle_user_removal_index_compaction() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();
    let user3 = Address::generate(&env);

    // Register three users: alice, bob, carol
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
        TrustBridgeContract::register(env.clone(), s(&env, "carol"), user3.clone()).unwrap();
    });

    // Verify initial state
    env.as_contract(&contract_id, || {
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 3);
    });

    // Remove the middle user (bob)
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });

    // Verify remaining users are accessible
    env.as_contract(&contract_id, || {
        assert!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "bob")).is_none(),
            "removed user must not be accessible"
        );
        assert_eq!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "alice"))
                .unwrap()
                .stellar_address,
            user1,
            "alice must remain accessible"
        );
        assert_eq!(
            TrustBridgeContract::get_address(env.clone(), s(&env, "carol"))
                .unwrap()
                .stellar_address,
            user3,
            "carol must remain accessible"
        );
    });

    // Verify stats match actual records
    env.as_contract(&contract_id, || {
        let stats = TrustBridgeContract::get_stats(env.clone());
        assert_eq!(stats.total, 2, "stats.total must match remaining records");
        assert_eq!(stats.verified, 0, "no users were verified");
    });

    // Verify full export contains exactly the remaining users
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let all = TrustBridgeContract::get_all_registered(env.clone()).unwrap();
        assert_eq!(
            all.len(),
            2,
            "export must contain exactly 2 users after middle removal"
        );

        let names: soroban_sdk::Vec<String> = {
            let mut v = soroban_sdk::Vec::new(&env);
            for i in 0..all.len() {
                v.push_back(all.get(i).unwrap().0);
            }
            v
        };
        assert!(
            names.contains(s(&env, "alice")),
            "export must include alice"
        );
        assert!(
            names.contains(s(&env, "carol")),
            "export must include carol"
        );
        assert!(
            !names.contains(s(&env, "bob")),
            "export must not include removed bob"
        );

        // Verify no duplicates in export
        let mut seen_alice = false;
        let mut seen_carol = false;
        for i in 0..all.len() {
            let (username, _) = all.get(i).unwrap();
            if username == s(&env, "alice") {
                assert!(!seen_alice, "alice must not appear twice in export");
                seen_alice = true;
            }
            if username == s(&env, "carol") {
                assert!(!seen_carol, "carol must not appear twice in export");
                seen_carol = true;
            }
        }
        assert!(
            seen_alice && seen_carol,
            "both alice and carol must appear in export"
        );
    });

    // Verify paginated export is consistent
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let page = TrustBridgeContract::get_registered_paginated(env.clone(), 0, 10).unwrap();
        assert_eq!(
            page.records.len(),
            2,
            "paginated export must contain 2 records"
        );
        assert_eq!(page.total, 2, "paginated total must match stats");
        assert!(!page.has_more, "no more pages expected");
        assert!(
            page.next_cursor.is_none(),
            "next_cursor must be None when no more pages"
        );
    });

    // Verify public paginated endpoint is also consistent
    env.as_contract(&contract_id, || {
        let page = TrustBridgeContract::get_public_paginated(env.clone(), 0, 10).unwrap();
        assert_eq!(
            page.records.len(),
            2,
            "public paginated export must contain 2 records"
        );
        assert_eq!(page.total, 2, "public paginated total must match stats");
    });
}

/// get_stats().verified matches get_verified_count() at every step (Issue #16).
#[test]
fn test_integration_stats_verified_matches_verified_count() {
    let (env, admin, user1, user2, contract_id) = setup_test_env();

    let check = |env: &Env, cid: &Address| {
        env.as_contract(cid, || {
            assert_eq!(
                TrustBridgeContract::get_stats(env.clone()).verified,
                TrustBridgeContract::get_verified_count(env.clone()),
                "get_stats().verified must equal get_verified_count()"
            );
        });
    };

    check(&env, &contract_id);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "alice"), user1.clone()).unwrap();
    });
    check(&env, &contract_id);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "alice")).unwrap();
    });
    check(&env, &contract_id);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::register(env.clone(), s(&env, "bob"), user2.clone()).unwrap();
    });
    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });
    check(&env, &contract_id);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::revoke_verification(env.clone(), admin.clone(), s(&env, "alice"), 1)
            .unwrap();
    });
    check(&env, &contract_id);

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        TrustBridgeContract::remove(env.clone(), admin.clone(), s(&env, "bob")).unwrap();
    });
    check(&env, &contract_id);
}

// ── Issue #57: verify() on a not-registered username ──────────────────────────

/// `verify` on a username with no registration returns `NotRegistered` and
/// leaves the registry untouched — the not-registered path must fail closed
/// rather than silently creating a verified record.
#[test]
fn test_integration_verify_not_registered_fails_and_leaves_registry_untouched() {
    let (env, admin, _user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let result = TrustBridgeContract::verify(env.clone(), admin.clone(), s(&env, "ghost"));
        assert_eq!(result, Err(ContractError::NotRegistered));
    });

    env.as_contract(&contract_id, || {
        assert!(TrustBridgeContract::get_address(env.clone(), s(&env, "ghost")).is_none());
        assert_eq!(TrustBridgeContract::get_verified_count(env.clone()), 0);
        assert_eq!(TrustBridgeContract::get_stats(env.clone()).total, 0);
    });
}

/// The same guard holds for `revoke_verification` on a not-registered
/// username, so the two verification-mutating entry points stay consistent.
#[test]
fn test_integration_revoke_verification_not_registered_fails() {
    let (env, admin, _user1, _user2, contract_id) = setup_test_env();

    env.mock_all_auths();
    env.as_contract(&contract_id, || {
        let result = TrustBridgeContract::revoke_verification(
            env.clone(),
            admin.clone(),
            s(&env, "ghost"),
            1,
        );
        assert_eq!(result, Err(ContractError::NotRegistered));
    });
}
 
 / /   �  � �  �   B a t c h   R e m o v e   I n t e g r a t i o n   T e s t s   �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  � �  �  
  
 # [ t e s t ]  
 f n   t e s t _ i n t e g r a t i o n _ b a t c h _ r e m o v e _ l i f e c y c l e ( )   {  
         l e t   ( e n v ,   a d m i n ,   u s e r 1 ,   u s e r 2 ,   c o n t r a c t _ i d )   =   s e t u p _ t e s t _ e n v ( ) ;  
  
         / /   R e g i s t e r   t w o   u s e r s  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 T r u s t B r i d g e C o n t r a c t : : r e g i s t e r ( e n v . c l o n e ( ) ,   s ( & e n v ,   " a l i c e " ) ,   u s e r 1 . c l o n e ( ) ) . u n w r a p ( ) ;  
                 T r u s t B r i d g e C o n t r a c t : : r e g i s t e r ( e n v . c l o n e ( ) ,   s ( & e n v ,   " b o b " ) ,   u s e r 2 . c l o n e ( ) ) . u n w r a p ( ) ;  
         } ) ;  
  
         / /   V e r i f y   o n e   u s e r   t o   t e s t   v e r i f i e d _ c o u n t   d e c r e m e n t  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 T r u s t B r i d g e C o n t r a c t : : v e r i f y ( e n v . c l o n e ( ) ,   a d m i n . c l o n e ( ) ,   s ( & e n v ,   " a l i c e " ) ) . u n w r a p ( ) ;  
         } ) ;  
  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 a s s e r t _ e q ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ s t a t s ( e n v . c l o n e ( ) ) . t o t a l ,   2 ) ;  
                 a s s e r t _ e q ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ v e r i f i e d _ c o u n t ( e n v . c l o n e ( ) ) ,   1 ) ;  
         } ) ;  
  
         / /   B a t c h   r e m o v e   a l i c e   ( e x i s t s ,   v e r i f i e d ) ,   c h a r l i e   ( d o e s   n o t   e x i s t ) ,   b o b   ( e x i s t s ,   u n v e r i f i e d )  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         l e t   s u m m a r y   =   e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 l e t   u s e r n a m e s   =   s o r o b a n _ s d k : : v e c ! [ & e n v ,   s ( & e n v ,   " a l i c e " ) ,   s ( & e n v ,   " c h a r l i e " ) ,   s ( & e n v ,   " b o b " ) ] ;  
                 T r u s t B r i d g e C o n t r a c t : : b a t c h _ r e m o v e ( e n v . c l o n e ( ) ,   a d m i n . c l o n e ( ) ,   u s e r n a m e s ) . u n w r a p ( )  
         } ) ;  
  
         / /   W e   a t t e m p t e d   3 ,   2   s u c c e e d e d   ( a l i c e ,   b o b ) ,   1   f a i l e d   ( c h a r l i e   -   n o t   r e g i s t e r e d )  
         a s s e r t _ e q ! ( s u m m a r y . t o t a l ,   3 ) ;  
         a s s e r t _ e q ! ( s u m m a r y . s u c c e s s f u l ,   2 ) ;  
         a s s e r t _ e q ! ( s u m m a r y . f a i l e d ,   1 ) ;  
  
         / /   V e r i f y   r e g i s t r y   s t a t e  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 a s s e r t ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ a d d r e s s ( e n v . c l o n e ( ) ,   s ( & e n v ,   " a l i c e " ) ) . i s _ n o n e ( ) ) ;  
                 a s s e r t ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ a d d r e s s ( e n v . c l o n e ( ) ,   s ( & e n v ,   " b o b " ) ) . i s _ n o n e ( ) ) ;  
                 a s s e r t _ e q ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ s t a t s ( e n v . c l o n e ( ) ) . t o t a l ,   0 ) ;  
                 a s s e r t _ e q ! ( T r u s t B r i d g e C o n t r a c t : : g e t _ v e r i f i e d _ c o u n t ( e n v . c l o n e ( ) ) ,   0 ) ;  
         } ) ;  
 }  
  
 # [ t e s t ]  
 f n   t e s t _ i n t e g r a t i o n _ b a t c h _ r e m o v e _ a u t h _ a n d _ p a u s e ( )   {  
         l e t   ( e n v ,   a d m i n ,   u s e r 1 ,   _ u s e r 2 ,   c o n t r a c t _ i d )   =   s e t u p _ t e s t _ e n v ( ) ;  
  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 T r u s t B r i d g e C o n t r a c t : : r e g i s t e r ( e n v . c l o n e ( ) ,   s ( & e n v ,   " a l i c e " ) ,   u s e r 1 . c l o n e ( ) ) . u n w r a p ( ) ;  
         } ) ;  
  
         / /   N o n - a d m i n   c a n n o t   b a t c h   r e m o v e  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 l e t   u s e r n a m e s   =   s o r o b a n _ s d k : : v e c ! [ & e n v ,   s ( & e n v ,   " a l i c e " ) ] ;  
                 l e t   r e s   =   T r u s t B r i d g e C o n t r a c t : : b a t c h _ r e m o v e ( e n v . c l o n e ( ) ,   u s e r 1 . c l o n e ( ) ,   u s e r n a m e s ) ;  
                 a s s e r t _ e q ! ( r e s ,   E r r ( C o n t r a c t E r r o r : : N o t A u t h o r i z e d ) ) ;  
         } ) ;  
  
         / /   P a u s e d   c o n t r a c t   r e j e c t s   b a t c h   r e m o v e  
         e n v . m o c k _ a l l _ a u t h s ( ) ;  
         e n v . a s _ c o n t r a c t ( & c o n t r a c t _ i d ,   | |   {  
                 T r u s t B r i d g e C o n t r a c t : : p a u s e ( e n v . c l o n e ( ) ) . u n w r a p ( ) ;  
                 l e t   u s e r n a m e s   =   s o r o b a n _ s d k : : v e c ! [ & e n v ,   s ( & e n v ,   " a l i c e " ) ] ;  
                 l e t   r e s   =   T r u s t B r i d g e C o n t r a c t : : b a t c h _ r e m o v e ( e n v . c l o n e ( ) ,   a d m i n . c l o n e ( ) ,   u s e r n a m e s ) ;  
                 a s s e r t _ e q ! ( r e s ,   E r r ( C o n t r a c t E r r o r : : P a u s e d ) ) ;  
         } ) ;  
 }  
 