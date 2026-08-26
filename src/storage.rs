//! Instance vs. persistent storage layout, TTL constants, and per-key rent
//! behavior are documented in `docs/STORAGE_RENT.md` — read that before
//! changing `TTL_THRESHOLD` / `TTL_BUMP` or adding a new persistent key.

use soroban_sdk::{symbol_short, Address, BytesN, Env, String, Symbol, Vec};

use crate::ContractError;

pub const VER_CFG_KEY: Symbol = symbol_short!("vrfy_cfg");

// ── Storage keys ────────────────────────────────────────────────────────────

pub const REG_KEY: Symbol = symbol_short!("reg");
/// Storage key for the admin address. `initialize` is the **only** place
/// that writes this key, gated by `AlreadyInitialized` so it can run once.
/// No other public entry point mutates it — the admin is immutable after
/// init; rotation requires redeploying a new instance. See
/// `docs/SECURITY.md#admin-key-management` (Issue #97).
pub const ADMIN_KEY: Symbol = symbol_short!("admin");
pub const COUNT_KEY: Symbol = symbol_short!("count");
pub const VCOUNT_KEY: Symbol = symbol_short!("vcount");
pub const INDEX_KEY: Symbol = symbol_short!("idx");
pub const PAUSED_KEY: Symbol = symbol_short!("pause");
pub const COOLDOWN_KEY: Symbol = symbol_short!("cdown");
// Pending reverify flag per username
pub const PENDING_REVERIFY_KEY: Symbol = symbol_short!("pend_rev");
// Emergency pause flag and timestamp
#[allow(dead_code)]
pub const EMERGENCY_PAUSE_KEY: Symbol = symbol_short!("emrg_ps");
#[allow(dead_code)]
pub const EMERGENCY_PAUSE_TS_KEY: Symbol = symbol_short!("emerg_ts");
pub const LAST_UPG_KEY: Symbol = symbol_short!("lastupg");
pub const VER_KEY: Symbol = symbol_short!("ver");
pub const ROLE_KEY: Symbol = symbol_short!("role");

/// Key prefix for chunked username index entries.
pub const CHUNK_KEY: Symbol = symbol_short!("chunk");
pub const CHUNK_CNT_KEY: Symbol = symbol_short!("chkcnt");
pub const LAST_ACT_KEY: Symbol = symbol_short!("lastact");
/// Key for the WASM provenance record (Wave #24).
pub const PROV_KEY: Symbol = symbol_short!("prov");
/// Key for the pending upgrade attestation (Wave #24).
pub const ATTEST_KEY: Symbol = symbol_short!("attest");
/// Key for audit log entries list.
pub const AUDIT_LOG_KEY: Symbol = symbol_short!("adt_log");
/// Key for audit stats.
pub const AUDIT_STATS_KEY: Symbol = symbol_short!("adt_stat");

/// Key for the pause reason code (Issue #211).
pub const PAUSE_REASON_KEY: Symbol = symbol_short!("p_reason");

/// Key for the reserved username set (Issue #213).
pub const RESERVED_KEY: Symbol = symbol_short!("reserved");

/// Maximum entries in the reserved username list (Issue #213).
pub const MAX_RESERVED: u32 = 200;

/// Key for the version stored at `storage::get_version` / `set_version`.
/// Aliased as VERSION_KEY for callers that use that name.
pub const VERSION_KEY: Symbol = VER_KEY;

// ── Pagination constants ─────────────────────────────────────────────────────

pub const DEFAULT_PAGE_LIMIT: u32 = 20;
pub const MAX_PAGE_LIMIT: u32 = 100;

/// Maximum number of usernames per chunked index entry.
pub const CHUNK_SIZE: u32 = 50;

// ── TTL constants (ledger-based, ~5s/ledger) ────────────────────────────────
//
// Stellar closes a ledger roughly every 5 seconds, so ~17,280 ledgers is a day.

/// Ledgers per day at the ~5s close time, used to express the policy in days.
pub const LEDGERS_PER_DAY: u32 = 17_280;

/// Persistent entries are bumped when their remaining TTL drops below this
/// (~30 days). `extend_ttl` is a no-op when the remaining TTL already exceeds
/// the threshold, so this is what keeps a hot record from paying the
/// extension cost on every single read.
pub const TTL_THRESHOLD: u32 = LEDGERS_PER_DAY * 30;

/// Extend to this many ledgers from the current one (~90 days). Comfortably
/// inside the network's maximum persistent TTL, so an extension is never
/// rejected for overshooting the cap.
pub const TTL_BUMP: u32 = LEDGERS_PER_DAY * 90;

// ── Types ────────────────────────────────────────────────────────────────────

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
#[repr(u32)]
pub enum Role {
    Admin = 1,
    Upgrader = 2,
    Verifier = 3,
}

/// Typed reason code for `pause`, `unpause`, and `set_paused` (Issue #211).
///
/// Stored on-chain alongside the pause flag so incident reviewers can
/// distinguish a maintenance pause from a security freeze without replaying
/// event history. All mutation entry points that flip the pause flag require
/// a valid `PauseReason`; unknown codes fail with
/// [`ContractError::InvalidPauseReason`].
///
/// | Code | Name | When to use |
/// |------|------|-------------|
/// | 1 | `Maintenance` | Planned upgrade window or admin maintenance |
/// | 2 | `SecurityIncident` | Freeze after a detected exploit or suspicious activity |
/// | 3 | `RegulatoryHold` | Compliance or legal hold requirement |
/// | 4 | `Unpause` | Resuming normal operation (used with `unpause`) |
/// | 99 | `Other` | Any reason not covered above |
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
#[repr(u32)]
pub enum PauseReason {
    Maintenance = 1,
    SecurityIncident = 2,
    RegulatoryHold = 3,
    Unpause = 4,
    Other = 99,
}

impl PauseReason {
    /// Returns `true` if `code` maps to a known `PauseReason` discriminant.
    #[must_use]
    pub fn is_valid(code: u32) -> bool {
        matches!(code, 1 | 2 | 3 | 4 | 99)
    }

    /// Converts a raw u32 to the corresponding `PauseReason`, or `None` for
    /// unrecognized codes.
    #[must_use]
    pub fn from_code(code: u32) -> Option<Self> {
        match code {
            1 => Some(PauseReason::Maintenance),
            2 => Some(PauseReason::SecurityIncident),
            3 => Some(PauseReason::RegulatoryHold),
            4 => Some(PauseReason::Unpause),
            99 => Some(PauseReason::Other),
            _ => None,
        }
    }
}

/// An on-chain record for a registered contributor.
///
/// Stored under `(Symbol("reg"), github_username)` in persistent storage.
/// TTL is extended on every read and write; use `extend_registry_ttl` to
/// refresh cold entries before they are archived.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct ContributorRecord {
    /// The Stellar G-address that owns this registration.
    pub stellar_address: Address,
    /// Ledger timestamp when this record was last written.
    ///
    /// Stored as `u32` instead of `u64` to save 4 bytes per record. Soroban
    /// ledger timestamps (Unix seconds) fit in u32 until ~2106 — well beyond
    /// the expected lifetime of any TrustBridge contract instance. The cast
    /// from `env.ledger().timestamp()` (`u64`) to `u32` is a deliberate
    /// truncation that will not wrap in practice.
    pub registered_at: u32,
    /// Whether the contributor has been verified by an admin or Verifier.
    pub verified: bool,
}

/// Provenance of the currently deployed WASM executable (Wave #24).
///
/// `upgrade` previously left no queryable trace of what it did — it wrote a
/// bare timestamp to `LAST_UPG_KEY` and published an event. Events are not
/// contract state: an auditor asking "what is deployed right now, and what did
/// it replace?" had to reconstruct the answer by replaying the whole event
/// history, and could not do it from a contract call at all.
///
/// This is the answer as a single readable record. `previous_wasm_hash` is what
/// makes it a chain rather than a snapshot: each record names its predecessor,
/// so the lineage can be walked backwards through historical `UpgradedEvent`s
/// even though only the head is stored.
/// Semantic version triple used by `WasmProvenance`.
///
/// Stored as a named struct so that `#[soroban_sdk::contracttype]` can
/// derive the XDR serialization — bare `(u32, u32, u32)` tuples are not
/// supported inside `Option` by the macro.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct VersionTriple {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct WasmProvenance {
    /// Hash of the WASM currently executing.
    pub wasm_hash: BytesN<32>,
    /// Hash this one replaced. `None` for the first upgrade after deployment.
    pub previous_wasm_hash: Option<BytesN<32>>,
    /// Address that authorised the upgrade.
    pub upgraded_by: Address,
    /// Ledger timestamp the upgrade was applied.
    pub upgraded_at: u64,
    /// Contract version recorded at upgrade time. Empty vec == unset.
    pub version: Vec<u32>,
    /// Whether the hash had been attested before it was applied.
    pub attested: bool,
}

/// An admin's advance declaration of the WASM hash they intend to deploy.
///
/// Optional two-step upgrade. When an attestation is live, `upgrade` will only
/// accept the hash it names — so a compromised admin key cannot swap in a
/// different binary at the moment of the upgrade without first publishing that
/// intent, on-chain, ahead of time.
///
/// The expiry is the point: an attestation that never lapsed would be a
/// standing authorisation for that hash, which is strictly worse than none.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct WasmAttestation {
    /// Hash the admin has declared they intend to deploy.
    pub wasm_hash: BytesN<32>,
    /// Ledger timestamp after which this attestation is no longer valid.
    pub expires_at: u64,
    /// Address that published the attestation.
    pub attested_by: Address,
    /// Ledger timestamp the attestation was published.
    pub attested_at: u64,
}

/// Aggregate registry statistics returned by `get_stats`.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct Stats {
    /// Total number of registered contributors.
    pub total: u32,
    /// Number of contributors who have been verified.
    pub verified: u32,
}

/// A single page of registry records returned by paginated export functions.
///
/// `next_cursor` is `None` when this is the last page. Pass it as `cursor` to
/// the next call to advance the page. `has_more` mirrors `next_cursor.is_some()`
/// for clients that prefer a boolean sentinel.
#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct ExportPage {
    /// Records in this page: `(github_username, ContributorRecord)` pairs.
    pub records: Vec<(String, ContributorRecord)>,
    /// Cursor to pass to the next call, or `None` if this is the last page.
    pub next_cursor: Option<u32>,
    /// Total number of records in the registry at query time.
    pub total: u32,
    /// `true` if there are more records after this page.
    pub has_more: bool,
}

// ── Initialization / admin ───────────────────────────────────────────────────

pub fn require_initialized(env: &Env) -> Result<(), ContractError> {
    if env.storage().instance().has(&ADMIN_KEY) {
        Ok(())
    } else {
        Err(ContractError::NotInitialized)
    }
}

pub fn get_admin(env: &Env) -> Result<Address, ContractError> {
    require_initialized(env)?;
    env.storage()
        .instance()
        .get(&ADMIN_KEY)
        .ok_or(ContractError::NotInitialized)
}

pub fn get_record(env: &Env, github_username: &String) -> Option<ContributorRecord> {
    let key = (REG_KEY, github_username.clone());
    let record: Option<ContributorRecord> = env.storage().persistent().get(&key);
    if record.is_some() {
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
    }
    record
}

pub fn set_record(env: &Env, github_username: &String, record: &ContributorRecord) {
    let key = (REG_KEY, github_username.clone());
    env.storage().persistent().set(&key, record);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
}

/// Extends a single record's TTL without deserialising it (Wave #7).
///
/// `get_record` also extends as a side effect of reading, but it pays to decode
/// the `ContributorRecord` first. A keeper bumping thousands of entries does not
/// want the value, only the extension — this skips that cost.
///
/// Returns whether the entry existed. A missing entry is not an error: the
/// keeper's list is built off-chain and can lag behind removals.
pub fn extend_record_ttl(env: &Env, github_username: &String) -> bool {
    let key = (REG_KEY, github_username.clone());
    if !env.storage().persistent().has(&key) {
        return false;
    }
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
    true
}

pub fn remove_record(env: &Env, github_username: &String) {
    let key = (REG_KEY, github_username.clone());
    env.storage().persistent().remove(&key);
}

pub fn has_record(env: &Env, github_username: &String) -> bool {
    get_record(env, github_username).is_some()
}

// ── Counters ─────────────────────────────────────────────────────────────────

pub fn get_count(env: &Env) -> u32 {
    env.storage().instance().get(&COUNT_KEY).unwrap_or(0)
}

pub fn set_count(env: &Env, count: u32) {
    env.storage().instance().set(&COUNT_KEY, &count);
}

pub fn get_verified_count(env: &Env) -> u32 {
    env.storage().instance().get(&VCOUNT_KEY).unwrap_or(0)
}

pub fn set_verified_count(env: &Env, count: u32) {
    env.storage().instance().set(&VCOUNT_KEY, &count);
}

// ── Flat username index ──────────────────────────────────────────────────────

pub fn get_index(env: &Env) -> Vec<String> {
    env.storage()
        .instance()
        .get(&INDEX_KEY)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn set_index(env: &Env, index: &Vec<String>) {
    env.storage().instance().set(&INDEX_KEY, index);
}

/// Returns a bounded page of usernames from the flat index starting at `offset`.
///
/// Used by `get_registered_page` for admin exports. Clamps `limit` to
/// `MAX_PAGE_LIMIT` and applies `DEFAULT_PAGE_LIMIT` when `limit == 0`.
pub fn get_index_page(env: &Env, offset: u32, limit: u32) -> Vec<String> {
    let index = get_index(env);
    let mut page = Vec::new(env);

    let effective_limit = if limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        limit.min(MAX_PAGE_LIMIT)
    };

    if offset >= index.len() {
        return page;
    }

    let end = offset.saturating_add(effective_limit).min(index.len());
    for i in offset..end {
        if let Some(u) = index.get(i) {
            page.push_back(u);
        }
    }
    page
}

// ── Chunked username index ───────────────────────────────────────────────────

pub fn get_chunk_count(env: &Env) -> u32 {
    env.storage().instance().get(&CHUNK_CNT_KEY).unwrap_or(0)
}

pub fn set_chunk_count(env: &Env, count: u32) {
    env.storage().instance().set(&CHUNK_CNT_KEY, &count);
}

pub fn get_chunk(env: &Env, chunk_idx: u32) -> Vec<String> {
    let key = (CHUNK_KEY, chunk_idx);
    let chunk: Vec<String> = env
        .storage()
        .persistent()
        .get(&key)
        .unwrap_or_else(|| Vec::new(env));
    if !chunk.is_empty() {
        env.storage()
            .persistent()
            .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
    }
    chunk
}

pub fn set_chunk(env: &Env, chunk_idx: u32, chunk: &Vec<String>) {
    let key = (CHUNK_KEY, chunk_idx);
    env.storage().persistent().set(&key, chunk);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
}

pub fn add_to_index(env: &Env, github_username: &String) {
    // 1. Maintain legacy single-vec index
    let mut index = get_index(env);
    index.push_back(github_username.clone());
    set_index(env, &index);

    // 2. Maintain chunked index
    let chunk_cnt = get_chunk_count(env);
    if chunk_cnt == 0 {
        let mut first_chunk = Vec::new(env);
        first_chunk.push_back(github_username.clone());
        set_chunk(env, 0, &first_chunk);
        set_chunk_count(env, 1);
    } else {
        let last_idx = chunk_cnt - 1;
        let mut last_chunk = get_chunk(env, last_idx);
        if last_chunk.len() >= CHUNK_SIZE {
            let mut new_chunk = Vec::new(env);
            new_chunk.push_back(github_username.clone());
            set_chunk(env, chunk_cnt, &new_chunk);
            set_chunk_count(env, chunk_cnt + 1);
        } else {
            last_chunk.push_back(github_username.clone());
            set_chunk(env, last_idx, &last_chunk);
        }
    }
}

/// Removes `github_username` from both the legacy flat index and the chunked
/// index.
///
/// Empty-registry invariant (Issue #92): removing the last remaining entry
/// must leave the legacy index at length 0 and the chunk that held it empty,
/// not a stale hole — `get_all_registered`, `get_index_page`, and the export
/// paths must all observe a clean empty registry afterward, and a subsequent
/// registration must proceed exactly as it would on a never-used registry.
/// Covered by `test_remove_last_user_returns_registry_to_empty_state` in
/// `src/lib.rs`.
pub fn remove_from_index(env: &Env, github_username: &String) {
    // 1. Legacy index update
    let index = get_index(env);
    let mut next = Vec::new(env);
    for i in 0..index.len() {
        let username = index.get(i).unwrap();
        if username != *github_username {
            next.push_back(username);
        }
    }
    set_index(env, &next);

    // 2. Chunked index update
    let chunk_cnt = get_chunk_count(env);
    for c in 0..chunk_cnt {
        let chunk = get_chunk(env, c);
        let mut new_chunk = Vec::new(env);
        let mut found = false;
        for i in 0..chunk.len() {
            let username = chunk.get(i).unwrap();
            if username == *github_username {
                found = true;
            } else {
                new_chunk.push_back(username);
            }
        }
        if found {
            set_chunk(env, c, &new_chunk);
            break;
        }
    }
}

// ── Paginated export (Issue #1 & #3) ─────────────────────────────────────────

/// Returns a bounded page of `(username, record)` pairs starting at `cursor`.
///
/// `limit == 0` falls back to `DEFAULT_PAGE_LIMIT`; anything above
/// `MAX_PAGE_LIMIT` is clamped down to it rather than rejected — a caller
/// asking for too much gets the largest page the contract allows instead of
/// an error.
pub fn get_registered_paginated_internal(
    env: &Env,
    cursor: u32,
    limit: u32,
) -> Result<ExportPage, ContractError> {
    require_initialized(env)?;

    let effective_limit = if limit == 0 {
        DEFAULT_PAGE_LIMIT
    } else {
        limit.min(MAX_PAGE_LIMIT)
    };

    let total_count = get_count(env);
    let mut records = Vec::new(env);

    if cursor >= total_count {
        return Ok(ExportPage {
            records,
            next_cursor: None,
            total: total_count,
            has_more: false,
        });
    }

    let index = get_index(env);
    let end = (cursor.saturating_add(effective_limit)).min(index.len());

    for i in cursor..end {
        if let Some(username) = index.get(i) {
            if let Some(record) = get_record(env, &username) {
                records.push_back((username, record));
            }
        }
    }

    let next_cursor = if end < index.len() { Some(end) } else { None };
    let has_more = next_cursor.is_some();

    Ok(ExportPage {
        records,
        next_cursor,
        total: total_count,
        has_more,
    })
}

// ── Stats ────────────────────────────────────────────────────────────────────

// Wave #41: build_stats is the single centralized constructor for `Stats`.
// All stats reads (get_stats, and any future indexer/dashboard aggregate
// endpoints) should route through it rather than building `Stats { .. }`
// literals directly, so count/verified-count semantics stay in one place.
pub fn build_stats(total: u32, verified: u32) -> Stats {
    Stats { total, verified }
}

pub fn get_stats(env: &Env) -> Stats {
    build_stats(get_count(env), get_verified_count(env))
}

// ── Cooldown / upgrade timelock ───────────────────────────────────────────────

pub fn get_cooldown(env: &Env) -> u64 {
    env.storage().instance().get(&COOLDOWN_KEY).unwrap_or(0)
}

#[allow(dead_code)]
pub fn get_emergency_pause(env: &Env) -> bool {
    env.storage()
        .instance()
        .get(&EMERGENCY_PAUSE_KEY)
        .unwrap_or(false)
}

#[allow(dead_code)]
pub fn set_emergency_pause(env: &Env, flag: bool) {
    env.storage().instance().set(&EMERGENCY_PAUSE_KEY, &flag);
}

#[allow(dead_code)]
pub fn get_emergency_pause_ts(env: &Env) -> u64 {
    env.storage()
        .instance()
        .get(&EMERGENCY_PAUSE_TS_KEY)
        .unwrap_or(0)
}

#[allow(dead_code)]
pub fn set_emergency_pause_ts(env: &Env, ts: u64) {
    env.storage().instance().set(&EMERGENCY_PAUSE_TS_KEY, &ts);
}

pub fn set_cooldown(env: &Env, cooldown_seconds: u64) {
    env.storage()
        .instance()
        .set(&COOLDOWN_KEY, &cooldown_seconds);
}

/// Returns `true` if the contract's pause flag is set.
pub fn is_paused(env: &Env) -> bool {
    env.storage().instance().get(&PAUSED_KEY).unwrap_or(false)
}

/// Rejects the call while the contract is paused.
pub fn require_not_paused(env: &Env) -> Result<(), ContractError> {
    if is_paused(env) {
        Err(ContractError::Paused)
    } else {
        Ok(())
    }
}

/// Sets the contract pause flag. Called by `pause` / `unpause`.
pub fn set_paused(env: &Env, paused: bool) {
    env.storage().instance().set(&PAUSED_KEY, &paused);
}

#[allow(dead_code)]
pub fn get_pending_reverify(env: &Env, github_username: &String) -> bool {
    let key = (PENDING_REVERIFY_KEY, github_username.clone());
    env.storage().persistent().get(&key).unwrap_or(false)
}

pub fn set_pending_reverify(env: &Env, github_username: &String, flag: bool) {
    let key = (PENDING_REVERIFY_KEY, github_username.clone());
    env.storage().persistent().set(&key, &flag);
}

pub fn clear_pending_reverify(env: &Env, github_username: &String) {
    let key = (PENDING_REVERIFY_KEY, github_username.clone());
    env.storage().persistent().remove(&key);
}

pub fn get_last_upgrade(env: &Env) -> u64 {
    env.storage().instance().get(&LAST_UPG_KEY).unwrap_or(0)
}

pub fn set_last_upgrade(env: &Env, timestamp: u64) {
    env.storage().instance().set(&LAST_UPG_KEY, &timestamp);
}

// ── Version ──────────────────────────────────────────────────────────────────

/// Returns the version recorded at initialize time, or `None` for instances
/// deployed before version tracking existed.
pub fn get_version(env: &Env) -> Option<(u32, u32, u32)> {
    env.storage().instance().get(&VERSION_KEY)
}

pub fn set_version(env: &Env, version: (u32, u32, u32)) {
    env.storage().instance().set(&VERSION_KEY, &version);
}

// ─── WASM provenance & attestation (Wave #24) ────────────────────────────────

/// Provenance of the currently deployed WASM. `None` before the first upgrade.
pub fn get_wasm_provenance(env: &Env) -> Option<WasmProvenance> {
    env.storage().instance().get(&PROV_KEY)
}

pub fn set_wasm_provenance(env: &Env, provenance: &WasmProvenance) {
    env.storage().instance().set(&PROV_KEY, provenance);
}

/// The pending upgrade attestation, if one has been published.
///
/// Returns the raw record regardless of expiry — callers decide what to do with
/// a lapsed attestation, and `get_wasm_attestation` is also a read endpoint
/// where seeing the expired value is useful for diagnosis.
pub fn get_wasm_attestation(env: &Env) -> Option<WasmAttestation> {
    env.storage().instance().get(&ATTEST_KEY)
}

pub fn set_wasm_attestation(env: &Env, attestation: &WasmAttestation) {
    env.storage().instance().set(&ATTEST_KEY, attestation);
}

pub fn remove_wasm_attestation(env: &Env) {
    env.storage().instance().remove(&ATTEST_KEY);
}

// ── Per-user action cooldown (Wave #33) ──────────────────────────────────────

/// Timestamp of `github_username`'s last cooldown-tracked action, or 0 if it
/// has none. Cooldown is tracked per username rather than globally so one
/// contributor's activity cannot block everyone else's.
pub fn get_last_action(env: &Env, github_username: &String) -> u64 {
    env.storage()
        .persistent()
        .get(&(LAST_ACT_KEY, github_username.clone()))
        .unwrap_or(0)
}

/// Records the ledger timestamp of the last mutating action for `github_username`.
pub fn set_last_action(env: &Env, github_username: &String, timestamp: u64) {
    let key = (LAST_ACT_KEY, github_username.clone());
    env.storage().persistent().set(&key, &timestamp);
    env.storage()
        .persistent()
        .extend_ttl(&key, TTL_THRESHOLD, TTL_BUMP);
}

/// True when the configured cooldown has not yet elapsed since
/// `github_username`'s last tracked action. A cooldown of 0 disables the
/// check entirely.
pub fn is_in_cooldown(env: &Env, github_username: &String) -> bool {
    let cooldown = get_cooldown(env);
    if cooldown == 0 {
        return false;
    }
    let last = get_last_action(env, github_username);
    if last == 0 {
        return false;
    }
    env.ledger().timestamp() < last.saturating_add(cooldown)
}

// ── Role-based access control ─────────────────────────────────────────────────

pub fn get_role(env: &Env, address: &Address) -> Option<Role> {
    env.storage().persistent().get(&(ROLE_KEY, address.clone()))
}

pub fn set_role(env: &Env, address: &Address, role: &Role) {
    env.storage()
        .persistent()
        .set(&(ROLE_KEY, address.clone()), role);
}

pub fn remove_role(env: &Env, address: &Address) {
    env.storage()
        .persistent()
        .remove(&(ROLE_KEY, address.clone()));
}

/// True when `address` is the contract admin.
pub fn is_admin_caller(env: &Env, address: &Address) -> bool {
    matches!(get_admin(env), Ok(admin) if admin == *address)
}

#[allow(dead_code)] // Staged for role-gated entry points; covered by role tests.
pub fn has_role_or_admin(env: &Env, address: &Address, expected_role: Role) -> bool {
    if let Ok(admin) = get_admin(env) {
        if *address == admin {
            return true;
        }
    }
    match get_role(env, address) {
        Some(Role::Admin) => true,
        Some(r) => r == expected_role,
        None => false,
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
#[soroban_sdk::contracttype]
pub struct VerificationConfig {
    pub attestation: Symbol,
    pub expires_in: u64,
    pub threshold: u32,
}

pub fn is_verification_configured(env: &Env) -> bool {
    env.storage().instance().has(&VER_CFG_KEY)
}

pub fn get_verification_config(env: &Env) -> Option<VerificationConfig> {
    env.storage().instance().get(&VER_CFG_KEY)
}

/// Stores the verification configuration. Idempotent — caller must gate
/// on [`is_verification_configured`] first.
pub fn set_verification_config(env: &Env, attestation: Symbol, expires_in: u64, threshold: u32) {
    let config = VerificationConfig {
        attestation,
        expires_in,
        threshold,
    };
    env.storage().instance().set(&VER_CFG_KEY, &config);
}

// ── Audit log persistence ──────────────────────────────────────────────────

pub const MAX_AUDIT_LOG_ENTRIES: u32 = 100;

pub fn get_audit_logs(env: &Env) -> Vec<crate::audit::AuditLogEntry> {
    env.storage()
        .instance()
        .get(&AUDIT_LOG_KEY)
        .unwrap_or_else(|| Vec::new(env))
}

pub fn push_audit_entry(env: &Env, entry: crate::audit::AuditLogEntry) {
    let mut logs = get_audit_logs(env);
    let mut stats = get_audit_stats(env);

    stats.record_event(entry.event_type);
    set_audit_stats(env, &stats);

    if logs.len() >= MAX_AUDIT_LOG_ENTRIES {
        logs.pop_front();
    }
    logs.push_back(entry);
    env.storage().instance().set(&AUDIT_LOG_KEY, &logs);
}

pub fn get_audit_stats(env: &Env) -> crate::audit::AuditStats {
    env.storage()
        .instance()
        .get(&AUDIT_STATS_KEY)
        .unwrap_or_default()
}

pub fn set_audit_stats(env: &Env, stats: &crate::audit::AuditStats) {
    env.storage().instance().set(&AUDIT_STATS_KEY, stats);
}

// ── Pause reason (Issue #211) ─────────────────────────────────────────────────

/// Returns the reason code stored when the contract was last paused or
/// unpaused. Returns `PauseReason::Other` (99) if no reason has been stored
/// yet (e.g. on instances initialized before reason tracking was added).
pub fn get_pause_reason(env: &Env) -> PauseReason {
    env.storage()
        .instance()
        .get(&PAUSE_REASON_KEY)
        .unwrap_or(PauseReason::Other)
}

/// Stores the pause/unpause reason alongside the pause flag.
pub fn set_pause_reason(env: &Env, reason: PauseReason) {
    env.storage().instance().set(&PAUSE_REASON_KEY, &reason);
}

// ── Reserved username list (Issue #213) ──────────────────────────────────────

/// Returns the current reserved username list.
pub fn get_reserved_list(env: &Env) -> Vec<String> {
    env.storage()
        .instance()
        .get(&RESERVED_KEY)
        .unwrap_or_else(|| Vec::new(env))
}

/// Overwrites the reserved username list.
pub fn set_reserved_list(env: &Env, list: &Vec<String>) {
    env.storage().instance().set(&RESERVED_KEY, list);
}

/// Returns `true` if `username` appears in the reserved list (case-insensitive).
pub fn is_reserved(env: &Env, username: &String) -> bool {
    let list = get_reserved_list(env);
    for i in 0..list.len() {
        if let Some(entry) = list.get(i) {
            if crate::utils::eq_ignore_ascii_case(&entry, username) {
                return true;
            }
        }
    }
    false
}

/// Adds `username` to the reserved list.
///
/// Returns `AlreadyReserved` if it is already present and
/// `ReservedListFull` if the list has reached `MAX_RESERVED`.
pub fn add_to_reserved(
    env: &Env,
    username: &String,
) -> Result<(), crate::ContractError> {
    let mut list = get_reserved_list(env);
    if is_reserved(env, username) {
        return Err(crate::ContractError::AlreadyReserved);
    }
    if list.len() >= MAX_RESERVED {
        return Err(crate::ContractError::ReservedListFull);
    }
    list.push_back(username.clone());
    set_reserved_list(env, &list);
    Ok(())
}

/// Removes `username` from the reserved list.
///
/// Returns `NotReserved` if it is not present.
pub fn remove_from_reserved(
    env: &Env,
    username: &String,
) -> Result<(), crate::ContractError> {
    let list = get_reserved_list(env);
    let mut next = Vec::new(env);
    let mut found = false;
    for i in 0..list.len() {
        if let Some(entry) = list.get(i) {
            if crate::utils::eq_ignore_ascii_case(&entry, username) {
                found = true;
            } else {
                next.push_back(entry);
            }
        }
    }
    if !found {
        return Err(crate::ContractError::NotReserved);
    }
    set_reserved_list(env, &next);
    Ok(())
}

// ── Index compaction (Issue #209) ─────────────────────────────────────────────

/// Rebuilds the chunked index densely from the legacy flat index.
///
/// After a wave of removals the chunked index can contain empty or
/// sparse slots. This operation re-partitions the current flat index
/// into full `CHUNK_SIZE` chunks plus a single partial tail, dropping
/// all holes. Callers observe no change in pagination results other
/// than the removal of empty gaps.
///
/// Returns the number of chunks written after compaction.
pub fn compact_chunked_index(env: &Env) -> u32 {
    let flat = get_index(env);
    let total = flat.len();

    // Delete all existing chunk entries.
    let old_cnt = get_chunk_count(env);
    for c in 0..old_cnt {
        let key = (CHUNK_KEY, c);
        env.storage().persistent().remove(&key);
    }

    if total == 0 {
        set_chunk_count(env, 0);
        return 0;
    }

    let mut chunk_idx: u32 = 0;
    let mut pos: u32 = 0;
    while pos < total {
        let end = pos.saturating_add(CHUNK_SIZE).min(total);
        let mut chunk: Vec<String> = Vec::new(env);
        for i in pos..end {
            if let Some(u) = flat.get(i) {
                chunk.push_back(u);
            }
        }
        set_chunk(env, chunk_idx, &chunk);
        chunk_idx = chunk_idx.saturating_add(1);
        pos = end;
    }

    set_chunk_count(env, chunk_idx);
    chunk_idx
}
