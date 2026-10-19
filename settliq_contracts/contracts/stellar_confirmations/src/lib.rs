#![no_std]

mod test;

use soroban_sdk::{
    contract, contractclient, contractimpl, contracttype, Address, BytesN, Env, String,
};

// ── payment_escrow cross-contract interface ─────────────────────────────────
//
// Minimal mirror of payment_escrow's `PaymentEscrow` record and `get_payment`
// entry point, following the same local-trait pattern liquidity_router uses
// for its AmmClient (see contracts/liquidity_router/src/lib.rs). Field names,
// types, and order must stay in sync with payment_escrow::PaymentEscrow.

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum PaymentEscrowAssetType {
    Xlm,
    Usdc,
}

#[contracttype]
#[derive(Clone, Debug, PartialEq)]
pub enum PaymentEscrowStatus {
    Pending,
    Disputed,
    Released,
    Expired,
}

#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentEscrowRecord {
    pub payment_id: BytesN<32>,
    pub amount: i128,
    pub released_amount: i128,
    pub merchant: Address,
    pub customer: Address,
    pub status: PaymentEscrowStatus,
    pub expiry: u32,
    pub dispute_window_end: u32,
    pub dispute_reason: Option<String>,
    pub asset_type: PaymentEscrowAssetType,
}

#[contractclient(name = "PaymentEscrowClient")]
pub trait PaymentEscrowInterface {
    fn get_payment(env: Env, payment_id: BytesN<32>) -> PaymentEscrowRecord;
}

// ── payment state consolidation (issue #74) ────────────────────────────────

/// Consolidated payment confirmation state (issue #74).
/// Combines 6 separate keys per payment into a single struct to reduce storage bloat.
#[contracttype]
#[derive(Clone, Debug)]
pub struct PaymentConfirmationState {
    pub confs: u32,              // confirmed count so far for a payment
    pub first_ledger: u32,       // ledger_seq of the first confirmation
    pub last_ledger: u32,        // ledger_seq of the most recent confirmation
    pub required_confs: u32,     // required count snapshotted at first confirmation
    pub settling: bool,          // already transitioned to settling state
    pub failed: bool,            // terminal failure state
}

// ── storage keys ────────────────────────────────────────────────────────────

#[contracttype]
enum DataKey {
    Admin,
    ConfirmationCount,          // required ledger-close count (u32)
    PaymentState(BytesN<32>),   // consolidated PaymentConfirmationState (issue #74)
    PaymentEscrowContract,      // optional Address of the payment_escrow contract
}
// ── events ───────────────────────────────────────────────────────────────────

#[contracttype]
struct ConfirmationRecordedEvent {
    payment_id: BytesN<32>,
    ledger_seq: u32,
    confirmations: u32,
    required: u32,
}

#[contracttype]
struct SettlementAuthorisedEvent {
    payment_id: BytesN<32>,
    ledger_seq: u32,   // ledger that pushed count over threshold
    amount: i128,      // informational — set by caller
    merchant: Address, // informational — set by caller
}

#[contracttype]
struct ConfirmationFailedEvent {
    payment_id: BytesN<32>,
    confirmations: u32, // confirmations accumulated at time of failure
    required: u32,
}

// ── contract ─────────────────────────────────────────────────────────────────

#[contract]
pub struct StellarConfirmationsContract;

#[contractimpl]
impl StellarConfirmationsContract {
    pub fn __constructor(env: Env, admin: Address, confirmation_count: u32) {
        assert!(confirmation_count > 0, "confirmation_count must be > 0");
        env.storage().instance().set(&DataKey::Admin, &admin);
        env.storage().instance().set(&DataKey::ConfirmationCount, &confirmation_count);
    }

    /// Called by the NestJS monitor once per observed Stellar ledger close.
    /// `ledger_seq` is the sequence number of the closed ledger.
    /// `amount` and `merchant` are forwarded into the SettlementAuthorised event
    /// so NestJS can trigger the fiat payout without a second lookup. When a
    /// payment_escrow contract has been configured via
    /// `set_payment_escrow_contract`, the final threshold-crossing call
    /// cross-checks `amount`/`merchant` against `payment_escrow::get_payment`
    /// and panics on a mismatch rather than trusting the caller blindly.
    ///
    /// Returns the current confirmation count after this call.
    pub fn confirm_payment(
        env: Env,
        caller: Address,
        payment_id: BytesN<32>,
        ledger_seq: u32,
        amount: i128,
        merchant: Address,
    ) -> u32 {
        caller.require_auth();
        Self::require_admin(&env, &caller);

        // Cross-contract check: if a payment_escrow contract is linked, verify
        // `amount`/`merchant` against the real on-chain payment record for
        // `payment_id` before recording this confirmation. This closes the gap
        // where a compromised/malfunctioning monitor could fabricate
        // confirmation/settlement events for arbitrary amount/merchant values.
        if let Some(escrow_address) = env
            .storage()
            .instance()
            .get::<_, Address>(&DataKey::PaymentEscrowContract)
        {
            let escrow_client = PaymentEscrowClient::new(&env, &escrow_address);
            let payment = escrow_client.get_payment(&payment_id);
            assert!(payment.amount == amount, "amount mismatch with payment_escrow record");
            assert!(payment.merchant == merchant, "merchant mismatch with payment_escrow record");
        }

        // Guard: ledger_seq must not be in the future relative to the actual chain state
        assert!(ledger_seq <= env.ledger().sequence(), "ledger_seq exceeds current ledger");

        // Load consolidated payment state (issue #74)
        let mut state = Self::load_payment_state(&env, &payment_id);

        // Guard: ledger_seq must be strictly greater than the last one recorded
        // for this payment. Allowing ledger_seq == last_seen would permit multiple
        // confirmations within the same ledger, enabling artificial inflation of
        // the confirmation counter to the threshold in a single ledger block and
        // invalidating the multi-ledger confirmation requirement.
        if state.last_ledger > 0 {
            assert!(ledger_seq > state.last_ledger, "ledger_seq must exceed last recorded ledger");
        }

        // Guard: already settling — idempotent no-op after threshold
        assert!(!state.settling, "payment already settling");

        // Guard: already failed — terminal state, cannot resume confirming
        assert!(!state.failed, "payment already failed");

        // Increment confirmation counter
        let new_confs = state.confs.checked_add(1).expect("overflow");

        // Record first-seen ledger for auditability (only on first confirmation)
        if state.first_ledger == 0 {
            state.first_ledger = ledger_seq;
        }

        // Record last-seen ledger for the monotonicity check above
        state.last_ledger = ledger_seq;
        state.confs = new_confs;

        // Snapshot the required confirmation count at first confirmation so
        // later admin changes to the global ConfirmationCount don't retroactively
        // move the threshold for payments already accumulating confirmations.
        let required: u32 = if state.required_confs == 0 {
            let current: u32 =
                env.storage().instance().get(&DataKey::ConfirmationCount).unwrap();
            state.required_confs = current;
            current
        } else {
            state.required_confs
        };

        // Save consolidated payment state (issue #74)
        Self::save_payment_state(&env, &payment_id, &state);

        env.events().publish(
            ("STELLAR_CONFS", "confirmation_recorded"),
            ConfirmationRecordedEvent {
                payment_id: payment_id.clone(),
                ledger_seq,
                confirmations: new_confs,
                required,
            },
        );

        // Transition to Settling when threshold is reached
        if new_confs >= required {
            // If a payment_escrow contract is configured, cross-check the
            // caller-supplied amount/merchant against the real escrow record
            // before trusting them to trigger an off-chain payout.
            if let Some(escrow_address) = Self::get_payment_escrow_contract(env.clone()) {
                let escrow_client = PaymentEscrowClient::new(&env, &escrow_address);
                let payment = escrow_client.get_payment(&payment_id);
                assert!(payment.amount == amount, "amount mismatch with payment_escrow");
                assert!(payment.merchant == merchant, "merchant mismatch with payment_escrow");
            }

            state.settling = true;
            Self::save_payment_state(&env, &payment_id, &state);

            env.events().publish(
                ("STELLAR_CONFS", "settlement_authorised"),
                SettlementAuthorisedEvent {
                    payment_id,
                    ledger_seq,
                    amount,
                    merchant,
                },
            );
        }

        new_confs
    }

    /// Admin: mark a stuck, sub-threshold payment as failed. This is the
    /// terminal failure state for a payment that never accumulates enough
    /// confirmations (e.g. a chain reorg or monitoring gap), mirroring the
    /// `fail` pattern in the `payment_request` contract.
    pub fn fail_confirmation(env: Env, caller: Address, payment_id: BytesN<32>) {
        caller.require_auth();
        Self::require_admin(&env, &caller);

        // Load consolidated payment state (issue #74)
        let mut state = Self::load_payment_state(&env, &payment_id);

        // Guard: cannot fail a payment that has already crossed the
        // threshold and is settling — that path is final.
        assert!(!state.settling, "payment already settling");

        // Guard: idempotent — cannot fail an already-failed payment.
        assert!(!state.failed, "payment already failed");

        state.failed = true;
        Self::save_payment_state(&env, &payment_id, &state);

        let required: u32 = if state.required_confs > 0 {
            state.required_confs
        } else {
            env.storage().instance().get(&DataKey::ConfirmationCount).unwrap()
        };

        env.events().publish(
            ("STELLAR_CONFS", "confirmation_failed"),
            ConfirmationFailedEvent {
                payment_id,
                confirmations: state.confs,
                required,
            },
        );
    }

    /// Admin: update the required confirmation count.
    pub fn set_confirmation_count(env: Env, caller: Address, count: u32) {
        caller.require_auth();
        Self::require_admin(&env, &caller);
        assert!(count > 0, "confirmation_count must be > 0");
        env.storage().instance().set(&DataKey::ConfirmationCount, &count);
    }

    pub fn get_confirmation_count(env: Env) -> u32 {
        env.storage().instance().get(&DataKey::ConfirmationCount).unwrap()
    }

    /// Admin: link the payment_escrow contract used to cross-check
    /// `amount`/`merchant` in `confirm_payment`. Pass `None` to unlink.
    pub fn set_payment_escrow_contract(env: Env, caller: Address, contract: Option<Address>) {
        caller.require_auth();
        Self::require_admin(&env, &caller);
        match contract {
            Some(addr) => env
                .storage()
                .instance()
                .set(&DataKey::PaymentEscrowContract, &addr),
            None => env.storage().instance().remove(&DataKey::PaymentEscrowContract),
        }
    }

    pub fn get_payment_escrow_contract(env: Env) -> Option<Address> {
        env.storage().instance().get(&DataKey::PaymentEscrowContract)
    }

    pub fn get_payment_confirmations(env: Env, payment_id: BytesN<32>) -> u32 {
        Self::load_payment_state(&env, &payment_id).confs
    }

    pub fn is_settling(env: Env, payment_id: BytesN<32>) -> bool {
        Self::load_payment_state(&env, &payment_id).settling
    }

    pub fn is_failed(env: Env, payment_id: BytesN<32>) -> bool {
        Self::load_payment_state(&env, &payment_id).failed
    }

    /// Returns the current admin address (issue #73).
    pub fn get_admin(env: Env) -> Address {
        env.storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic!("Admin not set"))
    }

    /// Transfers admin privileges to a new address (issue #73).
    pub fn transfer_admin(env: Env, caller: Address, new_admin: Address) {
        caller.require_auth();
        Self::require_admin(&env, &caller);
        env.storage().instance().set(&DataKey::Admin, &new_admin);
    }

    // ── Payment state consolidation helpers (issue #74) ──────────────────────

    /// Load consolidated payment state, defaulting to empty state if not found.
    fn load_payment_state(env: &Env, payment_id: &BytesN<32>) -> PaymentConfirmationState {
        env.storage()
            .persistent()
            .get::<_, PaymentConfirmationState>(&DataKey::PaymentState(payment_id.clone()))
            .unwrap_or(PaymentConfirmationState {
                confs: 0,
                first_ledger: 0,
                last_ledger: 0,
                required_confs: 0,
                settling: false,
                failed: false,
            })
    }

    /// Save consolidated payment state.
    fn save_payment_state(env: &Env, payment_id: &BytesN<32>, state: &PaymentConfirmationState) {
        env.storage()
            .persistent()
            .set(&DataKey::PaymentState(payment_id.clone()), state);
    }

    fn require_admin(env: &Env, caller: &Address) {
        let admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        assert!(caller == &admin, "not admin");
    }
}
