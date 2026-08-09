//! Durable, authenticated two-phase commit for cross-hub payments.
//!
//! Safety properties:
//! - every externally acknowledged transition is appended and fsynced first;
//! - prepare/commit/abort requests and acknowledgements are signed by pinned
//!   hub identities learned from signed hello;
//! - participant prepare and every phase transition are idempotent;
//! - a durable commit decision is irreversible and retried after restart;
//! - prepared participants never expire their reservation unilaterally.

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::sync::Mutex as AsyncMutex;
use tracing::warn;
use uuid::Uuid;

use crate::crypto::PaymentCommit;
use crate::net::NetClient;
use crate::state::{HubState, IdempotencyRecord, ReservedHop};
use crate::types::{PaymentSession, PaymentSignature, PaymentStatus};

pub const TX_PROTOCOL: &str = "hacash-l2-2pc/1";
const JOURNAL_VERSION: u32 = 2;
const REQUEST_MAX_AGE_SECS: u64 = 300;
const MAX_JOURNAL_BYTES: u64 = 512 * 1024 * 1024;

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

/// Debug-build-only process crash injection for multi-process durability tests.
/// Both variables are required so an accidentally inherited point name is inert.
#[inline]
fn chaos_crash_at(point: &'static str) {
    #[cfg(debug_assertions)]
    {
        let enabled = std::env::var("HACASH_L2_ENABLE_CHAOS").ok();
        let selected = std::env::var("HACASH_L2_CHAOS_CRASH_AT").ok();
        if enabled.as_deref() == Some("1") && selected.as_deref() == Some(point) {
            eprintln!("HACASH_L2_CHAOS_CRASH point={point}");
            // Immediate exit deliberately skips unwinding and destructors, matching
            // abrupt process loss after the preceding durable journal sync.
            std::process::exit(86);
        }
    }
    #[cfg(not(debug_assertions))]
    let _ = point;
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxPhase {
    Prepare,
    Commit,
    Abort,
}

impl TxPhase {
    fn as_str(self) -> &'static str {
        match self {
            Self::Prepare => "prepare",
            Self::Commit => "commit",
            Self::Abort => "abort",
        }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxRole {
    Coordinator,
    Participant,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum TxState {
    CoordinatorPreparing,
    CoordinatorPrepared,
    CoordinatorCommitDecided,
    CoordinatorCommitted,
    CoordinatorAbortDecided,
    CoordinatorAborted,
    ParticipantPrepared,
    ParticipantCommitDecided,
    ParticipantCommitted,
    ParticipantAborted,
}

impl TxState {
    fn as_str(self) -> &'static str {
        match self {
            Self::CoordinatorPreparing => "coordinator_preparing",
            Self::CoordinatorPrepared => "coordinator_prepared",
            Self::CoordinatorCommitDecided => "coordinator_commit_decided",
            Self::CoordinatorCommitted => "coordinator_committed",
            Self::CoordinatorAbortDecided => "coordinator_abort_decided",
            Self::CoordinatorAborted => "coordinator_aborted",
            Self::ParticipantPrepared => "participant_prepared",
            Self::ParticipantCommitDecided => "participant_commit_decided",
            Self::ParticipantCommitted => "participant_committed",
            Self::ParticipantAborted => "participant_aborted",
        }
    }

    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            Self::CoordinatorCommitted
                | Self::CoordinatorAborted
                | Self::ParticipantCommitted
                | Self::ParticipantAborted
        )
    }

    fn has_commit_decision(self) -> bool {
        matches!(
            self,
            Self::CoordinatorCommitDecided
                | Self::CoordinatorCommitted
                | Self::ParticipantCommitDecided
                | Self::ParticipantCommitted
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TxDescriptor {
    pub tx_id: Uuid,
    pub coordinator_provider_id: String,
    pub coordinator_public_url: String,
    pub participant_provider_id: String,
    /// Immutable user-signed payment fields. Every participant recomputes the hash.
    pub payment: PaymentCommit,
    pub payment_hash_hex: String,
    pub amount_zhu: u64,
    pub amount_satoshi: u64,
    pub expires_unix: u64,
    pub hops: Vec<ReservedHop>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxWireRequest {
    pub protocol: String,
    pub phase: TxPhase,
    pub descriptor: TxDescriptor,
    pub descriptor_hash_hex: String,
    pub timestamp_unix: u64,
    pub identity_address: String,
    pub identity_pubkey_hex: String,
    pub signature_hex: String,
    /// Present only for commit. Each participant verifies every user signature.
    #[serde(default)]
    pub payment_signatures: Vec<PaymentSignature>,
    pub authorization_hash_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxWireResponse {
    pub protocol: String,
    pub ok: bool,
    pub phase: TxPhase,
    pub tx_id: Uuid,
    pub descriptor_hash_hex: String,
    pub provider_id: String,
    pub coordinator_provider_id: String,
    pub state: TxState,
    pub timestamp_unix: u64,
    #[serde(default)]
    pub error: String,
    pub identity_address: String,
    pub identity_pubkey_hex: String,
    pub signature_hex: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxParticipant {
    pub descriptor: TxDescriptor,
    pub descriptor_hash_hex: String,
    pub prepared: bool,
    pub committed: bool,
    /// Durable acknowledgement of the coordinator's abort decision.
    #[serde(default)]
    pub aborted: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DistributedTransaction {
    pub tx_id: Uuid,
    pub role: TxRole,
    pub state: TxState,
    pub coordinator_provider_id: String,
    pub coordinator_public_url: String,
    pub payment_hash_hex: String,
    pub amount_zhu: u64,
    pub amount_satoshi: u64,
    pub expires_unix: u64,
    pub local_hops: Vec<ReservedHop>,
    pub participants: Vec<TxParticipant>,
    /// Coordinator recovery image. Refreshed when the commit decision records
    /// the complete verified signature set.
    #[serde(default)]
    pub coordinator_payment: Option<PaymentSession>,
    /// Content-bound client retry key, restored with the payment image.
    #[serde(default)]
    pub origin_idempotency: Option<(String, IdempotencyRecord)>,
    pub created_unix: u64,
    pub updated_unix: u64,
    #[serde(default)]
    pub last_error: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalCore {
    version: u32,
    sequence: u64,
    prev_hash_hex: String,
    transaction: DistributedTransaction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct JournalRecord {
    core: JournalCore,
    record_hash_hex: String,
}

#[derive(Debug, Clone)]
struct StoredTransaction {
    transaction: DistributedTransaction,
    last_sequence: u64,
    commit_sequence: Option<u64>,
}

#[derive(Debug, Default)]
struct JournalState {
    sequence: u64,
    last_hash_hex: String,
    transactions: HashMap<Uuid, StoredTransaction>,
}

#[derive(Debug)]
struct DurableTxJournal {
    path: PathBuf,
    state: Mutex<JournalState>,
}

impl DurableTxJournal {
    fn open(path: PathBuf) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent)
                    .map_err(|error| format!("create tx journal directory {parent:?}: {error}"))?;
            }
        }
        let state = replay_journal(&path)?;
        Ok(Self {
            path,
            state: Mutex::new(state),
        })
    }

    fn append(&self, transaction: DistributedTransaction) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|error| error.to_string())?;
        let existing_commit_sequence = state
            .transactions
            .get(&transaction.tx_id)
            .and_then(|stored| stored.commit_sequence);
        validate_journal_transition(
            state
                .transactions
                .get(&transaction.tx_id)
                .map(|stored| &stored.transaction),
            &transaction,
        )?;
        let sequence = state.sequence.saturating_add(1);
        let core = JournalCore {
            version: JOURNAL_VERSION,
            sequence,
            prev_hash_hex: state.last_hash_hex.clone(),
            transaction: transaction.clone(),
        };
        let core_value = serde_json::to_value(&core).map_err(|error| error.to_string())?;
        let record_hash_hex = hash_serializable(&core_value)?;
        let record = JournalRecord {
            core,
            record_hash_hex: record_hash_hex.clone(),
        };
        let mut bytes = serde_json::to_vec(&record).map_err(|error| error.to_string())?;
        bytes.push(b'\n');
        let existing_size = if self.path.exists() {
            fs::metadata(&self.path)
                .map_err(|error| format!("stat tx journal {:?}: {error}", self.path))?
                .len()
        } else {
            0
        };
        if existing_size.saturating_add(bytes.len() as u64) > MAX_JOURNAL_BYTES {
            return Err(format!(
                "tx journal would exceed safety cap of {MAX_JOURNAL_BYTES} bytes; compact offline"
            ));
        }

        let mut options = OpenOptions::new();
        options.create(true).append(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options
            .open(&self.path)
            .map_err(|error| format!("open tx journal {:?}: {error}", self.path))?;
        let durable_write = file
            .write_all(&bytes)
            .map_err(|error| format!("append tx journal {:?}: {error}", self.path))
            .and_then(|_| {
                file.sync_all()
                    .map_err(|error| format!("fsync tx journal {:?}: {error}", self.path))
            })
            .and_then(|_| sync_parent(&self.path));
        drop(file);
        if let Err(write_error) = durable_write {
            // A failed write/fsync has ambiguous durability. Re-read the file
            // before allowing any later append so sequence numbers cannot fork.
            match replay_journal(&self.path) {
                Ok(recovered) => *state = recovered,
                Err(replay_error) => {
                    return Err(format!(
                        "{write_error}; tx journal recovery also failed: {replay_error}"
                    ));
                }
            }
            return Err(write_error);
        }

        let commit_sequence = existing_commit_sequence
            .or_else(|| transaction.state.has_commit_decision().then_some(sequence));
        state.sequence = sequence;
        state.last_hash_hex = record_hash_hex;
        state.transactions.insert(
            transaction.tx_id,
            StoredTransaction {
                transaction,
                last_sequence: sequence,
                commit_sequence,
            },
        );
        Ok(())
    }

    fn get(&self, tx_id: Uuid) -> Option<DistributedTransaction> {
        self.state
            .lock()
            .ok()
            .and_then(|state| state.transactions.get(&tx_id).cloned())
            .map(|stored| stored.transaction)
    }

    fn list(&self) -> Vec<DistributedTransaction> {
        let mut stored: Vec<StoredTransaction> = self
            .state
            .lock()
            .map(|state| state.transactions.values().cloned().collect())
            .unwrap_or_default();
        stored.sort_by_key(|item| (item.commit_sequence.unwrap_or(u64::MAX), item.last_sequence));
        stored.into_iter().map(|item| item.transaction).collect()
    }
}

fn replay_journal(path: &Path) -> Result<JournalState, String> {
    if !path.exists() {
        return Ok(JournalState::default());
    }
    let mut file =
        File::open(path).map_err(|error| format!("open tx journal {path:?}: {error}"))?;
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .map_err(|error| format!("read tx journal {path:?}: {error}"))?;
    if bytes.len() as u64 > MAX_JOURNAL_BYTES {
        return Err(format!(
            "tx journal exceeds safety cap of {MAX_JOURNAL_BYTES} bytes"
        ));
    }

    let mut state = JournalState::default();
    let mut offset = 0usize;
    let mut valid_len = 0usize;
    while offset < bytes.len() {
        let Some(relative_newline) = bytes[offset..].iter().position(|byte| *byte == b'\n') else {
            break;
        };
        let line_end = offset + relative_newline;
        let line = &bytes[offset..line_end];
        offset = line_end + 1;
        valid_len = offset;
        if line.iter().all(u8::is_ascii_whitespace) {
            continue;
        }
        let raw_record: serde_json::Value = serde_json::from_slice(line).map_err(|error| {
            format!("corrupt complete tx journal record ending at byte {valid_len}: {error}")
        })?;
        let raw_core = raw_record
            .get("core")
            .ok_or_else(|| format!("tx journal record ending at byte {valid_len} has no core"))?;
        // Hash the raw JSON value so future defaulted fields do not alter replay.
        let expected_hash = hash_serializable(raw_core)?;
        let record: JournalRecord = serde_json::from_slice(line).map_err(|error| {
            format!("corrupt complete tx journal record ending at byte {valid_len}: {error}")
        })?;
        if record.core.version != JOURNAL_VERSION {
            return Err(format!(
                "unsupported tx journal version {}",
                record.core.version
            ));
        }
        let expected_sequence = state.sequence.saturating_add(1);
        if record.core.sequence != expected_sequence {
            return Err(format!(
                "tx journal sequence gap: expected {expected_sequence}, got {}",
                record.core.sequence
            ));
        }
        if record.core.prev_hash_hex != state.last_hash_hex {
            return Err(format!(
                "tx journal hash chain mismatch at sequence {}",
                record.core.sequence
            ));
        }
        if expected_hash != record.record_hash_hex {
            return Err(format!(
                "tx journal record hash mismatch at sequence {}",
                record.core.sequence
            ));
        }
        let tx = record.core.transaction;
        let previous_commit = state
            .transactions
            .get(&tx.tx_id)
            .and_then(|stored| stored.commit_sequence);
        let commit_sequence = previous_commit.or_else(|| {
            tx.state
                .has_commit_decision()
                .then_some(record.core.sequence)
        });
        validate_journal_transition(
            state
                .transactions
                .get(&tx.tx_id)
                .map(|stored| &stored.transaction),
            &tx,
        )?;
        state.sequence = record.core.sequence;
        state.last_hash_hex = record.record_hash_hex;
        state.transactions.insert(
            tx.tx_id,
            StoredTransaction {
                transaction: tx,
                last_sequence: state.sequence,
                commit_sequence,
            },
        );
    }

    // A non-newline-terminated tail can only be an interrupted append. It was
    // never acknowledged because append fsyncs the terminating newline.
    if valid_len < bytes.len() {
        let mut file = OpenOptions::new()
            .write(true)
            .open(path)
            .map_err(|error| format!("open torn tx journal tail {path:?}: {error}"))?;
        file.set_len(valid_len as u64)
            .map_err(|error| format!("truncate torn tx journal tail {path:?}: {error}"))?;
        file.seek(SeekFrom::Start(valid_len as u64))
            .map_err(|error| format!("seek tx journal {path:?}: {error}"))?;
        file.sync_all()
            .map_err(|error| format!("fsync repaired tx journal {path:?}: {error}"))?;
        sync_parent(path)?;
        chaos_crash_at("journal_after_tail_repair_fsync");
    }
    Ok(state)
}

fn hash_serializable<T: Serialize + ?Sized>(value: &T) -> Result<String, String> {
    let bytes = serde_json::to_vec(value).map_err(|error| error.to_string())?;
    Ok(hex::encode(crate::hacash_keys::sha3(bytes)))
}

fn validate_journal_transition(
    previous: Option<&DistributedTransaction>,
    next: &DistributedTransaction,
) -> Result<(), String> {
    let role_matches_state = match next.role {
        TxRole::Coordinator => matches!(
            next.state,
            TxState::CoordinatorPreparing
                | TxState::CoordinatorPrepared
                | TxState::CoordinatorCommitDecided
                | TxState::CoordinatorCommitted
                | TxState::CoordinatorAbortDecided
                | TxState::CoordinatorAborted
        ),
        TxRole::Participant => matches!(
            next.state,
            TxState::ParticipantPrepared
                | TxState::ParticipantCommitDecided
                | TxState::ParticipantCommitted
                | TxState::ParticipantAborted
        ),
    };
    if !role_matches_state {
        return Err("transaction role does not match journal state".into());
    }
    if next.payment_hash_hex.len() != 64
        || !next
            .payment_hash_hex
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("journal payment hash must be 32-byte hex".into());
    }
    for participant in &next.participants {
        if descriptor_hash_hex(&participant.descriptor)? != participant.descriptor_hash_hex {
            return Err("journal participant descriptor hash mismatch".into());
        }
    }
    if let Some((_, record)) = &next.origin_idempotency {
        if record.payment_id != next.tx_id {
            return Err("journal idempotency record points to another payment".into());
        }
    }
    if next.role == TxRole::Coordinator {
        let payment = next
            .coordinator_payment
            .as_ref()
            .ok_or_else(|| "coordinator journal entry lacks payment recovery image".to_string())?;
        if payment.id != next.tx_id || payment.message_hash_hex != next.payment_hash_hex {
            return Err("coordinator recovery image differs from transaction".into());
        }
    } else if next.coordinator_payment.is_some()
        || next.origin_idempotency.is_some()
        || !next.participants.is_empty()
    {
        return Err("participant journal entry contains coordinator-only data".into());
    }

    let Some(previous) = previous else {
        let valid_initial = matches!(
            (next.role, next.state),
            (TxRole::Coordinator, TxState::CoordinatorPreparing)
                | (TxRole::Participant, TxState::ParticipantPrepared)
                | (TxRole::Participant, TxState::ParticipantAborted)
        );
        return valid_initial
            .then_some(())
            .ok_or_else(|| "invalid initial distributed transaction state".into());
    };

    if previous.tx_id != next.tx_id
        || previous.role != next.role
        || previous.coordinator_provider_id != next.coordinator_provider_id
        || previous.coordinator_public_url != next.coordinator_public_url
        || previous.payment_hash_hex != next.payment_hash_hex
        || previous.amount_zhu != next.amount_zhu
        || previous.amount_satoshi != next.amount_satoshi
        || previous.expires_unix != next.expires_unix
        || previous.local_hops != next.local_hops
        || previous.created_unix != next.created_unix
        || previous.participants.len() != next.participants.len()
    {
        return Err("immutable distributed transaction fields changed".into());
    }
    for (old, new) in previous.participants.iter().zip(&next.participants) {
        if old.descriptor_hash_hex != new.descriptor_hash_hex || old.descriptor != new.descriptor {
            return Err("immutable participant descriptor changed".into());
        }
        if old.prepared && !new.prepared
            || old.committed && !new.committed
            || old.aborted && !new.aborted
            || new.committed && new.aborted
        {
            return Err("participant acknowledgement flags moved backwards or conflict".into());
        }
    }
    let valid_state = match previous.state {
        TxState::CoordinatorPreparing => matches!(
            next.state,
            TxState::CoordinatorPreparing
                | TxState::CoordinatorPrepared
                | TxState::CoordinatorAbortDecided
        ),
        TxState::CoordinatorPrepared => matches!(
            next.state,
            TxState::CoordinatorPrepared
                | TxState::CoordinatorCommitDecided
                | TxState::CoordinatorAbortDecided
        ),
        TxState::CoordinatorCommitDecided => matches!(
            next.state,
            TxState::CoordinatorCommitDecided | TxState::CoordinatorCommitted
        ),
        TxState::CoordinatorCommitted => next.state == TxState::CoordinatorCommitted,
        TxState::CoordinatorAbortDecided => matches!(
            next.state,
            TxState::CoordinatorAbortDecided | TxState::CoordinatorAborted
        ),
        TxState::CoordinatorAborted => next.state == TxState::CoordinatorAborted,
        TxState::ParticipantPrepared => matches!(
            next.state,
            TxState::ParticipantPrepared
                | TxState::ParticipantCommitDecided
                | TxState::ParticipantAborted
        ),
        TxState::ParticipantCommitDecided => matches!(
            next.state,
            TxState::ParticipantCommitDecided | TxState::ParticipantCommitted
        ),
        TxState::ParticipantCommitted => next.state == TxState::ParticipantCommitted,
        TxState::ParticipantAborted => next.state == TxState::ParticipantAborted,
    };
    valid_state
        .then_some(())
        .ok_or_else(|| "invalid durable distributed transaction state transition".into())
}

#[cfg(unix)]
fn sync_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        let directory = File::open(parent)
            .map_err(|error| format!("open tx journal directory {parent:?}: {error}"))?;
        directory
            .sync_all()
            .map_err(|error| format!("fsync tx journal directory {parent:?}: {error}"))?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) -> Result<(), String> {
    Ok(())
}

#[derive(Debug)]
pub struct DistributedTxManager {
    journal: Option<Arc<DurableTxJournal>>,
    transaction_locks: AsyncMutex<HashMap<Uuid, Arc<AsyncMutex<()>>>>,
}

impl DistributedTxManager {
    pub fn disabled() -> Self {
        Self {
            journal: None,
            transaction_locks: AsyncMutex::new(HashMap::new()),
        }
    }

    pub fn open(state_path: Option<&Path>) -> Result<Self, String> {
        let Some(state_path) = state_path else {
            return Ok(Self::disabled());
        };
        let journal_path = PathBuf::from(format!("{}.txlog", state_path.display()));
        Ok(Self {
            journal: Some(Arc::new(DurableTxJournal::open(journal_path)?)),
            transaction_locks: AsyncMutex::new(HashMap::new()),
        })
    }

    pub fn enabled(&self) -> bool {
        self.journal.is_some()
    }

    pub fn transaction(&self, tx_id: Uuid) -> Option<DistributedTransaction> {
        self.journal.as_ref().and_then(|journal| journal.get(tx_id))
    }

    pub fn transactions(&self) -> Vec<DistributedTransaction> {
        self.journal
            .as_ref()
            .map(|journal| journal.list())
            .unwrap_or_default()
    }

    pub fn prometheus_metrics(&self) -> String {
        let transactions = self.transactions();
        let count = |predicate: fn(TxState) -> bool| -> u64 {
            transactions
                .iter()
                .filter(|transaction| predicate(transaction.state))
                .count() as u64
        };
        let gauge = |name: &str, help: &str, value: u64| {
            format!("# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}\n")
        };
        let mut output = String::new();
        output.push_str(&gauge(
            "hacash_l2_distributed_transactions",
            "Transactions retained in the durable 2PC journal",
            transactions.len() as u64,
        ));
        output.push_str(&gauge(
            "hacash_l2_distributed_prepared",
            "Coordinator or participant transactions holding prepared liquidity",
            count(|state| {
                matches!(
                    state,
                    TxState::CoordinatorPrepared | TxState::ParticipantPrepared
                )
            }),
        ));
        output.push_str(&gauge(
            "hacash_l2_distributed_commit_pending",
            "Durable commit decisions awaiting local application or peer acknowledgements",
            count(|state| {
                matches!(
                    state,
                    TxState::CoordinatorCommitDecided | TxState::ParticipantCommitDecided
                )
            }),
        ));
        output.push_str(&gauge(
            "hacash_l2_distributed_abort_pending",
            "Durable coordinator abort decisions awaiting cleanup",
            count(|state| state == TxState::CoordinatorAbortDecided),
        ));
        output.push_str(&gauge(
            "hacash_l2_distributed_committed",
            "Durably committed distributed transactions",
            count(|state| {
                matches!(
                    state,
                    TxState::CoordinatorCommitted | TxState::ParticipantCommitted
                )
            }),
        ));
        output
    }

    async fn lock_for(&self, tx_id: Uuid) -> Arc<AsyncMutex<()>> {
        let mut locks = self.transaction_locks.lock().await;
        locks
            .entry(tx_id)
            .or_insert_with(|| Arc::new(AsyncMutex::new(())))
            .clone()
    }

    async fn append(&self, transaction: DistributedTransaction) -> Result<(), String> {
        let journal = self
            .journal
            .clone()
            .ok_or_else(|| "cross-hub requires --state-path for durable tx journal".to_string())?;
        tokio::task::spawn_blocking(move || journal.append(transaction))
            .await
            .map_err(|error| format!("tx journal worker failed: {error}"))?
    }

    async fn append_at(
        &self,
        transaction: DistributedTransaction,
        chaos_point: &'static str,
    ) -> Result<(), String> {
        self.append(transaction).await?;
        chaos_crash_at(chaos_point);
        Ok(())
    }

    pub async fn prepare_origin(
        &self,
        hub: &HubState,
        net: &NetClient,
        payment: &PaymentSession,
    ) -> Result<PaymentSession, String> {
        if payment.remote_hops.is_empty() {
            return Ok(payment.clone());
        }
        if !self.enabled() {
            return Err("cross-hub requires --state-path for durable tx journal".into());
        }
        if !net.distributed_identity_ready() {
            return Err(
                "cross-hub requires a local identity key and strict signed-hello verification"
                    .into(),
            );
        }
        let lock = self.lock_for(payment.id).await;
        let _guard = lock.lock().await;
        if let Some(existing) = self.transaction(payment.id) {
            return match existing.state {
                TxState::CoordinatorPrepared
                | TxState::CoordinatorCommitDecided
                | TxState::CoordinatorCommitted => hub
                    .get_payment(payment.id)
                    .ok_or_else(|| "coordinator payment missing".into()),
                TxState::CoordinatorAbortDecided | TxState::CoordinatorAborted => {
                    Err("distributed transaction was aborted".into())
                }
                _ => Err(format!(
                    "distributed transaction already exists in {:?}",
                    existing.state
                )),
            };
        }

        let local_reservation = hub
            .payment_reservation(payment.id)
            .ok_or_else(|| "origin local reservation missing".to_string())?;
        let participants = build_participants(hub, payment, net)?;
        let now = now_unix();
        let mut transaction = DistributedTransaction {
            tx_id: payment.id,
            role: TxRole::Coordinator,
            state: TxState::CoordinatorPreparing,
            coordinator_provider_id: net.local_provider().to_string(),
            coordinator_public_url: net.local_public_url().to_string(),
            payment_hash_hex: payment.message_hash_hex.clone(),
            amount_zhu: crate::amounts::parse_zhu(&payment.amount_hac)?,
            amount_satoshi: payment.amount_satoshi,
            expires_unix: payment.expires_unix,
            local_hops: local_reservation.hops,
            participants,
            coordinator_payment: Some(payment.clone()),
            origin_idempotency: hub.idempotency_for_payment(payment.id),
            created_unix: now,
            updated_unix: now,
            last_error: String::new(),
        };
        self.append_at(transaction.clone(), "coordinator_after_begin_fsync")
            .await?;

        for index in 0..transaction.participants.len() {
            let descriptor = transaction.participants[index].descriptor.clone();
            let request = signed_request(net, TxPhase::Prepare, descriptor, &[])?;
            let participant_url = hub
                .get_peer(&request.descriptor.participant_provider_id)
                .map(|peer| peer.public_url)
                .ok_or_else(|| {
                    format!(
                        "participant {} disappeared",
                        request.descriptor.participant_provider_id
                    )
                })?;
            let response = net.post_distributed_tx(&participant_url, &request).await;
            match response.and_then(|response| {
                verify_response(net, hub, &request, &response)?;
                if !response.ok || response.state != TxState::ParticipantPrepared {
                    return Err(if response.error.is_empty() {
                        format!("participant returned {:?}", response.state)
                    } else {
                        response.error
                    });
                }
                Ok(())
            }) {
                Ok(()) => {
                    transaction.participants[index].prepared = true;
                    transaction.updated_unix = now_unix();
                    self.append_at(transaction.clone(), "coordinator_after_prepare_ack_fsync")
                        .await?;
                }
                Err(error) => {
                    transaction.state = TxState::CoordinatorAbortDecided;
                    let prepare_error = format!(
                        "prepare failed at {}: {error}",
                        transaction.participants[index]
                            .descriptor
                            .participant_provider_id
                    );
                    transaction.last_error = prepare_error.clone();
                    transaction.updated_unix = now_unix();
                    self.append_at(
                        transaction.clone(),
                        "coordinator_after_abort_decision_fsync",
                    )
                    .await?;
                    // Abort every participant: a lost prepare acknowledgement is uncertain.
                    let abort_failures = self.deliver_abort(hub, net, &mut transaction).await;
                    let _ = hub.fail_payment(
                        payment.id,
                        "distributed prepare failed; durable abort decision recorded",
                    );
                    if abort_failures.is_empty()
                        && transaction
                            .participants
                            .iter()
                            .all(|participant| participant.aborted)
                    {
                        transaction.state = TxState::CoordinatorAborted;
                        transaction.last_error = prepare_error;
                    } else {
                        transaction.last_error = format!(
                            "{prepare_error}; abort acknowledgement pending: {}",
                            abort_failures.join("; ")
                        );
                    }
                    transaction.updated_unix = now_unix();
                    let chaos_point = if transaction.state == TxState::CoordinatorAborted {
                        "coordinator_after_abort_fsync"
                    } else {
                        "coordinator_after_abort_progress_fsync"
                    };
                    self.append_at(transaction, chaos_point).await?;
                    return Err(format!("distributed prepare failed: {error}"));
                }
            }
        }
        transaction.state = TxState::CoordinatorPrepared;
        transaction.updated_unix = now_unix();
        self.append_at(transaction, "coordinator_after_prepare_fsync")
            .await?;
        hub.get_payment(payment.id)
            .ok_or_else(|| "payment disappeared after distributed prepare".into())
    }

    pub async fn commit_origin_if_ready(
        &self,
        hub: &HubState,
        net: &NetClient,
        payment: &PaymentSession,
    ) -> Result<PaymentSession, String> {
        if payment.remote_hops.is_empty() {
            return Ok(payment.clone());
        }
        if payment.status != PaymentStatus::Committing {
            return Ok(payment.clone());
        }
        let lock = self.lock_for(payment.id).await;
        let _guard = lock.lock().await;
        self.commit_origin_locked(hub, net, payment.id).await
    }

    async fn commit_origin_locked(
        &self,
        hub: &HubState,
        net: &NetClient,
        tx_id: Uuid,
    ) -> Result<PaymentSession, String> {
        let mut transaction = self
            .transaction(tx_id)
            .ok_or_else(|| "distributed transaction journal entry missing".to_string())?;
        if transaction.role != TxRole::Coordinator {
            return Err("local hub is not transaction coordinator".into());
        }
        if matches!(
            transaction.state,
            TxState::CoordinatorAbortDecided | TxState::CoordinatorAborted
        ) {
            return Err("distributed transaction has an abort decision".into());
        }
        if transaction.state == TxState::CoordinatorCommitted {
            return hub
                .get_payment(tx_id)
                .ok_or_else(|| "committed payment missing".into());
        }
        let payment = hub
            .get_payment(tx_id)
            .ok_or_else(|| "coordinator payment missing".to_string())?;
        let all_signed = payment.required_signers.iter().all(|required| {
            payment
                .signatures
                .iter()
                .any(|signature| &signature.address == required)
        });
        if !all_signed {
            return Err("cannot commit distributed payment before all signatures".into());
        }
        if transaction.state == TxState::CoordinatorPreparing {
            return Err("cannot commit while participant prepare is incomplete".into());
        }
        if transaction.state == TxState::CoordinatorPrepared {
            transaction.state = TxState::CoordinatorCommitDecided;
            transaction.coordinator_payment = Some(payment.clone());
            transaction.last_error.clear();
            transaction.updated_unix = now_unix();
            // This append is the irreversible global decision.
            self.append_at(
                transaction.clone(),
                "coordinator_after_commit_decision_fsync",
            )
            .await?;
        }

        hub.apply_distributed_settlement(
            transaction.tx_id,
            transaction.amount_zhu,
            transaction.amount_satoshi,
            &transaction.local_hops,
        )?;
        chaos_crash_at("coordinator_after_local_apply");

        let mut failures = Vec::new();
        for index in 0..transaction.participants.len() {
            if transaction.participants[index].committed {
                continue;
            }
            let participant = transaction.participants[index].clone();
            match self
                .send_phase(hub, net, TxPhase::Commit, &participant, &payment.signatures)
                .await
            {
                Ok(()) => {
                    transaction.participants[index].committed = true;
                    transaction.updated_unix = now_unix();
                    self.append_at(transaction.clone(), "coordinator_after_commit_ack_fsync")
                        .await?;
                }
                Err(error) => failures.push(format!(
                    "{}: {error}",
                    participant.descriptor.participant_provider_id
                )),
            }
        }
        if !failures.is_empty() {
            transaction.last_error = failures.join("; ");
            transaction.updated_unix = now_unix();
            self.append_at(transaction, "coordinator_after_commit_progress_fsync")
                .await?;
            hub.mark_distributed_committing(tx_id, "durable commit decided; waiting for peer ack")?;
            return hub
                .get_payment(tx_id)
                .ok_or_else(|| "committing payment missing".into());
        }

        transaction.state = TxState::CoordinatorCommitted;
        transaction.last_error.clear();
        transaction.updated_unix = now_unix();
        self.append_at(transaction, "coordinator_after_commit_fsync")
            .await?;
        hub.mark_distributed_settled(tx_id)
    }

    async fn deliver_abort(
        &self,
        hub: &HubState,
        net: &NetClient,
        transaction: &mut DistributedTransaction,
    ) -> Vec<String> {
        let mut failures = Vec::new();
        for index in 0..transaction.participants.len() {
            if transaction.participants[index].aborted {
                continue;
            }
            let participant = transaction.participants[index].clone();
            match self
                .send_phase(hub, net, TxPhase::Abort, &participant, &[])
                .await
            {
                Ok(()) => {
                    transaction.participants[index].aborted = true;
                    transaction.updated_unix = now_unix();
                    if let Err(error) = self
                        .append_at(transaction.clone(), "coordinator_after_abort_ack_fsync")
                        .await
                    {
                        failures.push(format!(
                            "{} acknowledgement persistence: {error}",
                            participant.descriptor.participant_provider_id
                        ));
                    }
                }
                Err(error) => failures.push(format!(
                    "{}: {error}",
                    participant.descriptor.participant_provider_id
                )),
            }
        }
        failures
    }

    pub async fn abort_origin(
        &self,
        hub: &HubState,
        net: &NetClient,
        tx_id: Uuid,
        reason: &str,
    ) -> Result<PaymentSession, String> {
        let Some(mut transaction) = self.transaction(tx_id) else {
            return hub.fail_payment(tx_id, reason);
        };
        if transaction.role != TxRole::Coordinator {
            return Err("local hub is not transaction coordinator".into());
        }
        let lock = self.lock_for(tx_id).await;
        let _guard = lock.lock().await;
        transaction = self
            .transaction(tx_id)
            .ok_or_else(|| "transaction disappeared".to_string())?;
        if transaction.state.has_commit_decision() {
            return Err("cannot abort after durable commit decision".into());
        }
        if transaction.state == TxState::CoordinatorAborted {
            return hub
                .get_payment(tx_id)
                .ok_or_else(|| "aborted payment missing".into());
        }
        if transaction.state != TxState::CoordinatorAbortDecided {
            transaction.state = TxState::CoordinatorAbortDecided;
            transaction.last_error = reason.chars().take(256).collect();
            transaction.updated_unix = now_unix();
            self.append_at(
                transaction.clone(),
                "coordinator_after_abort_decision_fsync",
            )
            .await?;
        }
        let failures = self.deliver_abort(hub, net, &mut transaction).await;
        let payment = hub.fail_payment(tx_id, reason);
        if failures.is_empty()
            && transaction
                .participants
                .iter()
                .all(|participant| participant.aborted)
        {
            transaction.state = TxState::CoordinatorAborted;
            transaction.last_error.clear();
        } else {
            transaction.last_error = format!(
                "durable abort acknowledgement pending: {}",
                failures.join("; ")
            );
            for failure in &failures {
                warn!(tx_id = %tx_id, error = %failure, "distributed abort acknowledgement pending");
            }
        }
        transaction.updated_unix = now_unix();
        let chaos_point = if transaction.state == TxState::CoordinatorAborted {
            "coordinator_after_abort_fsync"
        } else {
            "coordinator_after_abort_progress_fsync"
        };
        self.append_at(transaction, chaos_point).await?;
        payment
    }

    async fn send_phase(
        &self,
        hub: &HubState,
        net: &NetClient,
        phase: TxPhase,
        participant: &TxParticipant,
        payment_signatures: &[PaymentSignature],
    ) -> Result<(), String> {
        let request = signed_request(
            net,
            phase,
            participant.descriptor.clone(),
            payment_signatures,
        )?;
        let peer = hub
            .get_peer(&participant.descriptor.participant_provider_id)
            .ok_or_else(|| {
                format!(
                    "participant {} not in peer table",
                    participant.descriptor.participant_provider_id
                )
            })?;
        let response = net.post_distributed_tx(&peer.public_url, &request).await?;
        verify_response(net, hub, &request, &response)?;
        if !response.ok {
            return Err(if response.error.is_empty() {
                format!("participant rejected {}", phase.as_str())
            } else {
                response.error
            });
        }
        let expected = match phase {
            TxPhase::Prepare => TxState::ParticipantPrepared,
            TxPhase::Commit => TxState::ParticipantCommitted,
            TxPhase::Abort => TxState::ParticipantAborted,
        };
        if response.state != expected {
            return Err(format!(
                "participant state {:?}, expected {:?}",
                response.state, expected
            ));
        }
        Ok(())
    }

    pub async fn handle_participant_request(
        &self,
        hub: &HubState,
        net: &NetClient,
        request: TxWireRequest,
    ) -> Result<TxWireResponse, String> {
        if !self.enabled() {
            return Err("participant requires --state-path for durable tx journal".into());
        }
        verify_request(net, hub, &request)?;
        if request.descriptor.participant_provider_id != hub.provider_id() {
            return Err("request participant_provider_id is not this hub".into());
        }
        if request.descriptor.expires_unix > 0
            && request.phase == TxPhase::Prepare
            && now_unix() >= request.descriptor.expires_unix
        {
            return Err("prepare request already expired".into());
        }
        let lock = self.lock_for(request.descriptor.tx_id).await;
        let _guard = lock.lock().await;
        let descriptor_hash = descriptor_hash_hex(&request.descriptor)?;
        let existing = self.transaction(request.descriptor.tx_id);
        if let Some(ref transaction) = existing {
            validate_existing_descriptor(transaction, &request.descriptor, &descriptor_hash)?;
        }
        let state = match request.phase {
            TxPhase::Prepare => {
                if let Some(transaction) = existing {
                    match transaction.state {
                        TxState::ParticipantPrepared => TxState::ParticipantPrepared,
                        TxState::ParticipantCommitDecided => {
                            return Err(
                                "commit decision recorded; local settlement recovery pending"
                                    .into(),
                            )
                        }
                        TxState::ParticipantCommitted => TxState::ParticipantCommitted,
                        TxState::ParticipantAborted => {
                            return Err("transaction already aborted".into())
                        }
                        other => {
                            return Err(format!("invalid participant state {other:?}"));
                        }
                    }
                } else {
                    hub.prepare_distributed_reservation(
                        request.descriptor.tx_id,
                        request.descriptor.amount_zhu,
                        request.descriptor.amount_satoshi,
                        &request.descriptor.hops,
                        request.descriptor.expires_unix,
                    )?;
                    let now = now_unix();
                    let transaction = DistributedTransaction {
                        tx_id: request.descriptor.tx_id,
                        role: TxRole::Participant,
                        state: TxState::ParticipantPrepared,
                        coordinator_provider_id: request.descriptor.coordinator_provider_id.clone(),
                        coordinator_public_url: request.descriptor.coordinator_public_url.clone(),
                        payment_hash_hex: request.descriptor.payment_hash_hex.clone(),
                        amount_zhu: request.descriptor.amount_zhu,
                        amount_satoshi: request.descriptor.amount_satoshi,
                        expires_unix: request.descriptor.expires_unix,
                        local_hops: request.descriptor.hops.clone(),
                        participants: Vec::new(),
                        coordinator_payment: None,
                        origin_idempotency: None,
                        created_unix: now,
                        updated_unix: now,
                        last_error: String::new(),
                    };
                    if let Err(error) = self
                        .append_at(transaction, "participant_after_prepare_fsync")
                        .await
                    {
                        hub.release_distributed_reservation(request.descriptor.tx_id);
                        return Err(error);
                    }
                    TxState::ParticipantPrepared
                }
            }
            TxPhase::Commit => {
                let mut transaction =
                    existing.ok_or_else(|| "commit received before prepare".to_string())?;
                match transaction.state {
                    TxState::ParticipantCommitted => TxState::ParticipantCommitted,
                    TxState::ParticipantAborted => {
                        return Err("commit conflicts with durable abort".into())
                    }
                    TxState::ParticipantPrepared | TxState::ParticipantCommitDecided => {
                        if transaction.state == TxState::ParticipantPrepared {
                            transaction.state = TxState::ParticipantCommitDecided;
                            transaction.updated_unix = now_unix();
                            self.append_at(
                                transaction.clone(),
                                "participant_after_commit_decision_fsync",
                            )
                            .await?;
                        }
                        hub.apply_distributed_settlement(
                            transaction.tx_id,
                            transaction.amount_zhu,
                            transaction.amount_satoshi,
                            &transaction.local_hops,
                        )?;
                        chaos_crash_at("participant_after_local_apply");
                        transaction.state = TxState::ParticipantCommitted;
                        transaction.last_error.clear();
                        transaction.updated_unix = now_unix();
                        self.append_at(transaction, "participant_after_commit_fsync")
                            .await?;
                        TxState::ParticipantCommitted
                    }
                    other => return Err(format!("invalid participant state {other:?}")),
                }
            }
            TxPhase::Abort => {
                if let Some(mut transaction) = existing {
                    if transaction.state.has_commit_decision() {
                        return Err("abort conflicts with durable commit decision".into());
                    }
                    if transaction.state != TxState::ParticipantAborted {
                        transaction.state = TxState::ParticipantAborted;
                        transaction.updated_unix = now_unix();
                        self.append_at(transaction, "participant_after_abort_fsync")
                            .await?;
                        hub.release_distributed_reservation(request.descriptor.tx_id);
                    }
                } else {
                    let now = now_unix();
                    let transaction = DistributedTransaction {
                        tx_id: request.descriptor.tx_id,
                        role: TxRole::Participant,
                        state: TxState::ParticipantAborted,
                        coordinator_provider_id: request.descriptor.coordinator_provider_id.clone(),
                        coordinator_public_url: request.descriptor.coordinator_public_url.clone(),
                        payment_hash_hex: request.descriptor.payment_hash_hex.clone(),
                        amount_zhu: request.descriptor.amount_zhu,
                        amount_satoshi: request.descriptor.amount_satoshi,
                        expires_unix: request.descriptor.expires_unix,
                        local_hops: request.descriptor.hops.clone(),
                        participants: Vec::new(),
                        coordinator_payment: None,
                        origin_idempotency: None,
                        created_unix: now,
                        updated_unix: now,
                        last_error: String::new(),
                    };
                    self.append_at(transaction, "participant_after_abort_tombstone_fsync")
                        .await?;
                    hub.release_distributed_reservation(request.descriptor.tx_id);
                }
                TxState::ParticipantAborted
            }
        };
        signed_response(net, &request, state, true, "")
    }

    /// Rebuild reservations and replay irrevocable local commits before serving.
    pub fn recover_local(&self, hub: &HubState) -> Result<usize, String> {
        let mut recovered = 0usize;
        for transaction in self.transactions() {
            if transaction.role == TxRole::Coordinator {
                let commit_decision_is_authoritative = transaction.state.has_commit_decision();
                if hub.get_payment(transaction.tx_id).is_none() || commit_decision_is_authoritative
                {
                    let payment = transaction.coordinator_payment.clone().ok_or_else(|| {
                        format!(
                            "coordinator journal {} lacks payment recovery image",
                            transaction.tx_id
                        )
                    })?;
                    if commit_decision_is_authoritative {
                        hub.restore_distributed_commit_payment(payment)?;
                    } else {
                        hub.restore_distributed_payment(payment)?;
                    }
                }
                if let Some((key, record)) = transaction.origin_idempotency.clone() {
                    hub.restore_distributed_idempotency(key, record);
                }
            }
            match transaction.state {
                TxState::ParticipantPrepared | TxState::CoordinatorPrepared => {
                    hub.prepare_distributed_reservation(
                        transaction.tx_id,
                        transaction.amount_zhu,
                        transaction.amount_satoshi,
                        &transaction.local_hops,
                        transaction.expires_unix,
                    )?;
                    recovered += 1;
                }
                TxState::ParticipantCommitDecided
                | TxState::ParticipantCommitted
                | TxState::CoordinatorCommitDecided
                | TxState::CoordinatorCommitted => {
                    let _ = hub.prepare_distributed_reservation(
                        transaction.tx_id,
                        transaction.amount_zhu,
                        transaction.amount_satoshi,
                        &transaction.local_hops,
                        transaction.expires_unix,
                    );
                    hub.apply_distributed_settlement(
                        transaction.tx_id,
                        transaction.amount_zhu,
                        transaction.amount_satoshi,
                        &transaction.local_hops,
                    )?;
                    if transaction.role == TxRole::Coordinator {
                        if transaction.state == TxState::CoordinatorCommitted {
                            let _ = hub.mark_distributed_settled(transaction.tx_id)?;
                        } else {
                            hub.mark_distributed_committing(
                                transaction.tx_id,
                                "recovered durable commit decision",
                            )?;
                        }
                    }
                    recovered += 1;
                }
                TxState::ParticipantAborted
                | TxState::CoordinatorAbortDecided
                | TxState::CoordinatorAborted => {
                    hub.release_distributed_reservation(transaction.tx_id);
                    if transaction.role == TxRole::Coordinator {
                        let _ = hub.fail_payment(
                            transaction.tx_id,
                            "recovered durable distributed abort decision",
                        );
                    }
                    recovered += 1;
                }
                TxState::CoordinatorPreparing => {
                    // No commit decision exists. Recovery uses presumed-abort.
                    hub.release_distributed_reservation(transaction.tx_id);
                }
            }
        }
        Ok(recovered)
    }

    /// Retry durable coordinator decisions. Participants never guess a decision.
    pub async fn retry_pending(&self, hub: &HubState, net: &NetClient) -> usize {
        let mut progressed = 0usize;
        for transaction in self.transactions() {
            if transaction.role != TxRole::Coordinator {
                continue;
            }
            if transaction.state == TxState::CoordinatorCommitted {
                if hub
                    .get_payment(transaction.tx_id)
                    .is_some_and(|payment| payment.status == PaymentStatus::Settled)
                {
                    continue;
                }
                let result = hub
                    .apply_distributed_settlement(
                        transaction.tx_id,
                        transaction.amount_zhu,
                        transaction.amount_satoshi,
                        &transaction.local_hops,
                    )
                    .and_then(|_| hub.mark_distributed_settled(transaction.tx_id))
                    .map(|_| ());
                match result {
                    Ok(()) => progressed += 1,
                    Err(error) => warn!(
                        tx_id = %transaction.tx_id,
                        %error,
                        "committed transaction local reconciliation pending"
                    ),
                }
                continue;
            }
            if transaction.state.is_terminal() {
                continue;
            }
            let lock = self.lock_for(transaction.tx_id).await;
            let Ok(_guard) = lock.try_lock() else {
                continue;
            };
            let result = match transaction.state {
                TxState::CoordinatorCommitDecided => self
                    .commit_origin_locked(hub, net, transaction.tx_id)
                    .await
                    .map(|_| ()),
                TxState::CoordinatorPrepared => {
                    let payment = hub.get_payment(transaction.tx_id);
                    if let Some(payment) = payment {
                        let all_signed = payment.required_signers.iter().all(|required| {
                            payment
                                .signatures
                                .iter()
                                .any(|signature| &signature.address == required)
                        });
                        if all_signed || payment.status == PaymentStatus::Committing {
                            self.commit_origin_locked(hub, net, transaction.tx_id)
                                .await
                                .map(|_| ())
                        } else if transaction.expires_unix > 0
                            && now_unix() >= transaction.expires_unix
                        {
                            drop(_guard);
                            self.abort_origin(
                                hub,
                                net,
                                transaction.tx_id,
                                "distributed payment expired before commit decision",
                            )
                            .await
                            .map(|_| ())
                        } else {
                            continue;
                        }
                    } else {
                        Err("coordinator payment missing during recovery".into())
                    }
                }
                TxState::CoordinatorPreparing => {
                    drop(_guard);
                    self.abort_origin(
                        hub,
                        net,
                        transaction.tx_id,
                        "recovery presumed abort for incomplete prepare",
                    )
                    .await
                    .map(|_| ())
                }
                TxState::CoordinatorAbortDecided => {
                    drop(_guard);
                    self.abort_origin(
                        hub,
                        net,
                        transaction.tx_id,
                        "retrying durable abort decision",
                    )
                    .await
                    .map(|_| ())
                }
                _ => continue,
            };
            match result {
                Ok(()) => progressed += 1,
                Err(error) => warn!(
                    tx_id = %transaction.tx_id,
                    %error,
                    "distributed transaction recovery retry pending"
                ),
            }
        }
        progressed
    }
}

fn build_participants(
    hub: &HubState,
    payment: &PaymentSession,
    net: &NetClient,
) -> Result<Vec<TxParticipant>, String> {
    let amount_zhu = crate::amounts::parse_zhu(&payment.amount_hac)?;
    let mut grouped: HashMap<String, Vec<ReservedHop>> = HashMap::new();
    for remote in &payment.remote_hops {
        if remote.from_address.trim().is_empty() || remote.to_address.trim().is_empty() {
            return Err(format!(
                "remote hop {} lacks signed direction metadata",
                remote.channel_id
            ));
        }
        grouped
            .entry(remote.via_provider.clone())
            .or_default()
            .push(ReservedHop {
                channel_id: remote.channel_id.clone(),
                from_address: remote.from_address.clone(),
                to_address: remote.to_address.clone(),
            });
    }
    let mut providers: Vec<String> = grouped.keys().cloned().collect();
    providers.sort();
    let mut participants = Vec::with_capacity(providers.len());
    for provider_id in providers {
        let peer = hub
            .get_peer(&provider_id)
            .ok_or_else(|| format!("remote provider {provider_id} not in peer table"))?;
        if !peer
            .meta
            .features
            .iter()
            .any(|feature| feature == "distributed-2pc")
        {
            return Err(format!(
                "remote provider {provider_id} does not advertise distributed-2pc"
            ));
        }
        if peer.meta.identity_address.is_empty() || peer.meta.identity_pubkey_hex.is_empty() {
            return Err(format!(
                "remote provider {provider_id} has no pinned signed identity"
            ));
        }
        if !peer.identity_verified {
            return Err(format!(
                "remote provider {provider_id} has no verified signed hello"
            ));
        }
        let descriptor = TxDescriptor {
            tx_id: payment.id,
            coordinator_provider_id: net.local_provider().to_string(),
            coordinator_public_url: net.local_public_url().to_string(),
            participant_provider_id: provider_id,
            payment_hash_hex: payment.message_hash_hex.clone(),
            amount_zhu,
            payment: HubState::payment_commit(payment, net.local_provider()),
            amount_satoshi: payment.amount_satoshi,
            expires_unix: payment.expires_unix,
            hops: grouped.remove(&peer.provider_id).unwrap_or_default(),
        };
        let descriptor_hash_hex = descriptor_hash_hex(&descriptor)?;
        participants.push(TxParticipant {
            descriptor,
            descriptor_hash_hex,
            prepared: false,
            committed: false,
            aborted: false,
        });
    }
    Ok(participants)
}

pub fn descriptor_hash_hex(descriptor: &TxDescriptor) -> Result<String, String> {
    hash_serializable(descriptor)
}

fn request_hash(request: &TxWireRequest) -> Result<[u8; 32], String> {
    let message = format!(
        "HACASH_L2_2PC_REQUEST_V1\nprotocol={}\nphase={}\ndescriptor_hash_hex={}\nauthorization_hash_hex={}\ntimestamp_unix={}\nidentity_address={}\n",
        request.protocol,
        request.phase.as_str(),
        request.descriptor_hash_hex,
        request.authorization_hash_hex,
        request.timestamp_unix,
        request.identity_address
    );
    Ok(crate::hacash_keys::sha3(message.as_bytes()))
}

fn response_hash(response: &TxWireResponse) -> Result<[u8; 32], String> {
    let message = format!(
        "HACASH_L2_2PC_RESPONSE_V1\nprotocol={}\nok={}\nphase={}\ntx_id={}\ndescriptor_hash_hex={}\nprovider_id={}\ncoordinator_provider_id={}\nstate={}\ntimestamp_unix={}\nerror_len={}\nerror={}\nidentity_address={}\n",
        response.protocol,
        response.ok,
        response.phase.as_str(),
        response.tx_id,
        response.descriptor_hash_hex,
        response.provider_id,
        response.coordinator_provider_id,
        response.state.as_str(),
        response.timestamp_unix,
        response.error.len(),
        response.error,
        response.identity_address
    );
    Ok(crate::hacash_keys::sha3(message.as_bytes()))
}

fn signed_request(
    net: &NetClient,
    phase: TxPhase,
    descriptor: TxDescriptor,
    payment_signatures: &[PaymentSignature],
) -> Result<TxWireRequest, String> {
    let descriptor_hash_hex = descriptor_hash_hex(&descriptor)?;
    let authorization_hash_hex = hash_serializable(payment_signatures)?;
    let (identity_address, identity_pubkey_hex) = net.local_identity_public()?;
    let mut request = TxWireRequest {
        protocol: TX_PROTOCOL.into(),
        phase,
        descriptor,
        descriptor_hash_hex,
        timestamp_unix: now_unix(),
        identity_address,
        identity_pubkey_hex,
        payment_signatures: payment_signatures.to_vec(),
        authorization_hash_hex,
        signature_hex: String::new(),
    };
    request.signature_hex = net.sign_protocol_hash(&request_hash(&request)?)?;
    Ok(request)
}

fn signed_response(
    net: &NetClient,
    request: &TxWireRequest,
    state: TxState,
    ok: bool,
    error: &str,
) -> Result<TxWireResponse, String> {
    let (identity_address, identity_pubkey_hex) = net.local_identity_public()?;
    let mut response = TxWireResponse {
        protocol: TX_PROTOCOL.into(),
        ok,
        phase: request.phase,
        tx_id: request.descriptor.tx_id,
        descriptor_hash_hex: request.descriptor_hash_hex.clone(),
        provider_id: request.descriptor.participant_provider_id.clone(),
        coordinator_provider_id: request.descriptor.coordinator_provider_id.clone(),
        state,
        timestamp_unix: now_unix(),
        error: error.chars().take(512).collect(),
        identity_address,
        identity_pubkey_hex,
        signature_hex: String::new(),
    };
    response.signature_hex = net.sign_protocol_hash(&response_hash(&response)?)?;
    Ok(response)
}

fn verify_timestamp(timestamp_unix: u64) -> Result<(), String> {
    let now = now_unix();
    if timestamp_unix > now.saturating_add(120) {
        return Err("2pc timestamp too far in the future".into());
    }
    if now.saturating_sub(timestamp_unix) > REQUEST_MAX_AGE_SECS {
        return Err("2pc signed message expired".into());
    }
    Ok(())
}

fn verify_request(net: &NetClient, hub: &HubState, request: &TxWireRequest) -> Result<(), String> {
    if request.protocol != TX_PROTOCOL {
        return Err("unsupported distributed transaction protocol".into());
    }
    validate_descriptor_payment(&request.descriptor)?;
    validate_participant_coverage(hub, &request.descriptor)?;
    validate_payment_authorization(request)?;
    if !net.distributed_identity_ready() {
        return Err("strict signed hub identity required for distributed transactions".into());
    }
    verify_timestamp(request.timestamp_unix)?;
    if request.descriptor.coordinator_provider_id == request.descriptor.participant_provider_id {
        return Err("coordinator and participant must differ".into());
    }
    if request.descriptor.payment_hash_hex.len() != 64
        || !request
            .descriptor
            .payment_hash_hex
            .chars()
            .all(|character| character.is_ascii_hexdigit())
    {
        return Err("payment_hash_hex must be 32-byte hex".into());
    }
    if request.descriptor.hops.is_empty() || request.descriptor.hops.len() > 32 {
        return Err("participant hops must contain 1..=32 entries".into());
    }
    let expected_descriptor_hash = descriptor_hash_hex(&request.descriptor)?;
    if expected_descriptor_hash != request.descriptor_hash_hex {
        return Err("descriptor hash mismatch".into());
    }
    net.verify_peer_protocol_hash(
        hub,
        &request.descriptor.coordinator_provider_id,
        &request.identity_address,
        &request.identity_pubkey_hex,
        &request.signature_hex,
        &request_hash(request)?,
    )
}

fn validate_descriptor_payment(descriptor: &TxDescriptor) -> Result<(), String> {
    let payment = &descriptor.payment;
    if payment.session_id != descriptor.tx_id.to_string() {
        return Err("payment session id does not match distributed transaction".into());
    }
    if payment.provider_id != descriptor.coordinator_provider_id {
        return Err("payment provider is not the distributed coordinator".into());
    }
    if crate::crypto::message_hash_hex(payment) != descriptor.payment_hash_hex {
        return Err("distributed descriptor does not reproduce the user payment hash".into());
    }
    if crate::amounts::parse_zhu(&payment.amount_hac)? != descriptor.amount_zhu
        || payment.amount_satoshi != descriptor.amount_satoshi
    {
        return Err("distributed amount differs from user payment commitment".into());
    }
    if payment.route.is_empty()
        || payment.route.len() > 32
        || payment.required_signers.len() != payment.route.len().saturating_add(1)
    {
        return Err("payment route must be a simple path with 1..=32 hops".into());
    }
    if descriptor.amount_zhu == 0 && descriptor.amount_satoshi == 0 {
        return Err("distributed payment amount cannot be zero".into());
    }
    let mut unique_channels = std::collections::HashSet::new();
    if payment
        .route
        .iter()
        .any(|channel_id| !unique_channels.insert(channel_id))
    {
        return Err("distributed payment route repeats a channel".into());
    }
    let mut addresses = payment.required_signers.clone();
    let mut unique_addresses = std::collections::HashSet::new();
    if addresses
        .iter()
        .any(|address| !unique_addresses.insert(address.clone()))
    {
        return Err("distributed payment signer path repeats an address".into());
    }
    addresses.reverse();
    if addresses.first().map(String::as_str) != Some(payment.payer.as_str())
        || addresses.last().map(String::as_str) != Some(payment.payee.as_str())
    {
        return Err("ordered signers do not connect payer to payee".into());
    }
    let mut local_channels = std::collections::HashSet::new();
    for hop in &descriptor.hops {
        if !local_channels.insert(hop.channel_id.clone()) {
            return Err("participant descriptor repeats a channel".into());
        }
        let index = payment
            .route
            .iter()
            .position(|channel_id| channel_id == &hop.channel_id)
            .ok_or_else(|| {
                format!(
                    "participant channel {} is absent from user-signed route",
                    hop.channel_id
                )
            })?;
        if addresses.get(index) != Some(&hop.from_address)
            || addresses.get(index.saturating_add(1)) != Some(&hop.to_address)
        {
            return Err(format!(
                "participant direction for {} differs from user-signed path",
                hop.channel_id
            ));
        }
    }
    Ok(())
}

fn validate_payment_authorization(request: &TxWireRequest) -> Result<(), String> {
    let expected_authorization_hash = hash_serializable(&request.payment_signatures)?;
    if expected_authorization_hash != request.authorization_hash_hex {
        return Err("payment authorization hash mismatch".into());
    }
    if request.phase != TxPhase::Commit {
        if !request.payment_signatures.is_empty() {
            return Err("user signatures are only valid on commit".into());
        }
        return Ok(());
    }
    let required = &request.descriptor.payment.required_signers;
    if request.payment_signatures.len() != required.len() {
        return Err("commit does not contain every required user signature".into());
    }
    let hash_bytes = hex::decode(&request.descriptor.payment_hash_hex)
        .map_err(|error| format!("decode payment hash: {error}"))?;
    if hash_bytes.len() != 32 {
        return Err("payment hash must be 32 bytes".into());
    }
    let mut payment_hash = [0u8; 32];
    payment_hash.copy_from_slice(&hash_bytes);
    for (index, required_address) in required.iter().enumerate() {
        let signature = request
            .payment_signatures
            .iter()
            .find(|signature| &signature.address == required_address)
            .ok_or_else(|| format!("missing signature from {required_address}"))?;
        if signature.order_index != index {
            return Err(format!(
                "signature order index for {required_address} is not {index}"
            ));
        }
        let public_key = (!signature.public_key_hex.trim().is_empty())
            .then_some(signature.public_key_hex.as_str());
        crate::crypto::verify_payment_signature(
            &payment_hash,
            required_address,
            &signature.signature_hex,
            public_key,
        )?;
    }
    Ok(())
}

fn verify_response(
    net: &NetClient,
    hub: &HubState,
    request: &TxWireRequest,
    response: &TxWireResponse,
) -> Result<(), String> {
    if response.protocol != TX_PROTOCOL
        || response.phase != request.phase
        || response.tx_id != request.descriptor.tx_id
        || response.descriptor_hash_hex != request.descriptor_hash_hex
        || response.provider_id != request.descriptor.participant_provider_id
        || response.coordinator_provider_id != request.descriptor.coordinator_provider_id
    {
        return Err("distributed transaction acknowledgement does not match request".into());
    }
    verify_timestamp(response.timestamp_unix)?;
    net.verify_peer_protocol_hash(
        hub,
        &response.provider_id,
        &response.identity_address,
        &response.identity_pubkey_hex,
        &response.signature_hex,
        &response_hash(response)?,
    )
}

fn validate_existing_descriptor(
    transaction: &DistributedTransaction,
    descriptor: &TxDescriptor,
    descriptor_hash: &str,
) -> Result<(), String> {
    if transaction.role != TxRole::Participant {
        return Err("transaction id already used by a coordinator record".into());
    }
    let expected = TxDescriptor {
        tx_id: transaction.tx_id,
        coordinator_provider_id: transaction.coordinator_provider_id.clone(),
        coordinator_public_url: transaction.coordinator_public_url.clone(),
        participant_provider_id: descriptor.participant_provider_id.clone(),
        payment_hash_hex: transaction.payment_hash_hex.clone(),
        amount_zhu: transaction.amount_zhu,
        payment: descriptor.payment.clone(),
        amount_satoshi: transaction.amount_satoshi,
        expires_unix: transaction.expires_unix,
        hops: transaction.local_hops.clone(),
    };
    if descriptor_hash_hex(&expected)? != descriptor_hash || &expected != descriptor {
        return Err("transaction id reused with different immutable descriptor".into());
    }
    Ok(())
}

pub async fn recovery_loop(
    manager: Arc<DistributedTxManager>,
    hub: Arc<HubState>,
    net: NetClient,
    interval_secs: u64,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(5)));
    loop {
        tick.tick().await;
        let progressed = manager.retry_pending(&hub, &net).await;
        if progressed > 0 {
            tracing::info!(progressed, "distributed transaction recovery progressed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    use axum::{
        extract::State,
        http::StatusCode,
        response::{IntoResponse, Response},
        routing::post,
        Json, Router,
    };

    #[derive(Clone)]
    struct TestParticipantHttp {
        hub: Arc<HubState>,
        net: NetClient,
        manager: Arc<DistributedTxManager>,
        lose_first_commit_ack: Arc<AtomicBool>,
        commit_requests: Arc<AtomicUsize>,
        lose_first_abort_ack: Arc<AtomicBool>,
        abort_requests: Arc<AtomicUsize>,
    }

    async fn participant_http_phase(
        State(state): State<TestParticipantHttp>,
        Json(request): Json<TxWireRequest>,
    ) -> Response {
        let phase = request.phase;
        match state
            .manager
            .handle_participant_request(&state.hub, &state.net, request)
            .await
        {
            Ok(response) => {
                if phase == TxPhase::Commit {
                    state.commit_requests.fetch_add(1, Ordering::SeqCst);
                    if state.lose_first_commit_ack.swap(false, Ordering::SeqCst) {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({
                                "ok": false,
                                "err": "simulated lost commit acknowledgement",
                            })),
                        )
                            .into_response();
                    }
                }
                if phase == TxPhase::Abort {
                    state.abort_requests.fetch_add(1, Ordering::SeqCst);
                    if state.lose_first_abort_ack.swap(false, Ordering::SeqCst) {
                        return (
                            StatusCode::SERVICE_UNAVAILABLE,
                            Json(serde_json::json!({
                                "ok": false,
                                "err": "simulated lost abort acknowledgement",
                            })),
                        )
                            .into_response();
                    }
                }
                Json(response).into_response()
            }
            Err(error) => (
                StatusCode::CONFLICT,
                Json(serde_json::json!({
                    "ok": false,
                    "err": error,
                })),
            )
                .into_response(),
        }
    }

    fn payment_signature_request(
        account: &crate::hacash_keys::Account,
        payment: &PaymentSession,
    ) -> crate::types::SignPaymentRequest {
        let decoded = hex::decode(&payment.message_hash_hex).unwrap();
        let hash: [u8; 32] = decoded.try_into().unwrap();
        crate::types::SignPaymentRequest {
            address: account.readable().into(),
            signature_hex: crate::crypto::sign_payment_hash(account, &hash),
            public_key_hex: String::new(),
        }
    }

    fn descriptor() -> TxDescriptor {
        TxDescriptor {
            tx_id: Uuid::new_v4(),
            coordinator_provider_id: "HubA".into(),
            coordinator_public_url: "http://127.0.0.1:9090".into(),
            participant_provider_id: "HubB".into(),
            payment_hash_hex: "11".repeat(32),
            amount_zhu: 100,
            payment: PaymentCommit {
                session_id: String::new(),
                provider_id: "HubA".into(),
                payer: "payer".into(),
                payee: "payee".into(),
                amount_hac: "1:248".into(),
                amount_satoshi: 2,
                fee_hac: "0".into(),
                route: vec!["22".repeat(16)],
                required_signers: vec!["payee".into(), "payer".into()],
                created_unix: now_unix(),
            },
            amount_satoshi: 2,
            expires_unix: now_unix() + 60,
            hops: vec![ReservedHop {
                channel_id: "22".repeat(16),
                from_address: "payer".into(),
                to_address: "payee".into(),
            }],
        }
    }

    fn transaction(state: TxState) -> DistributedTransaction {
        let descriptor = descriptor();
        DistributedTransaction {
            tx_id: descriptor.tx_id,
            role: TxRole::Participant,
            state,
            coordinator_provider_id: descriptor.coordinator_provider_id,
            coordinator_public_url: descriptor.coordinator_public_url,
            payment_hash_hex: descriptor.payment_hash_hex,
            amount_zhu: descriptor.amount_zhu,
            amount_satoshi: descriptor.amount_satoshi,
            expires_unix: descriptor.expires_unix,
            local_hops: descriptor.hops,
            participants: Vec::new(),
            coordinator_payment: None,
            origin_idempotency: None,
            created_unix: now_unix(),
            updated_unix: now_unix(),
            last_error: String::new(),
        }
    }

    #[test]
    fn journal_replays_hash_chained_commit_decision() {
        let path = std::env::temp_dir().join(format!("hacash-l2-2pc-{}.jsonl", Uuid::new_v4()));
        let journal = DurableTxJournal::open(path.clone()).unwrap();
        let mut tx = transaction(TxState::ParticipantPrepared);
        journal.append(tx.clone()).unwrap();
        tx.state = TxState::ParticipantCommitDecided;
        journal.append(tx.clone()).unwrap();
        tx.state = TxState::ParticipantCommitted;
        journal.append(tx.clone()).unwrap();
        drop(journal);

        let reopened = DurableTxJournal::open(path.clone()).unwrap();
        let restored = reopened.get(tx.tx_id).unwrap();
        assert_eq!(restored.state, TxState::ParticipantCommitted);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn torn_unacknowledged_tail_is_truncated() {
        let path = std::env::temp_dir().join(format!("hacash-l2-2pc-{}.jsonl", Uuid::new_v4()));
        let journal = DurableTxJournal::open(path.clone()).unwrap();
        let tx = transaction(TxState::ParticipantPrepared);
        journal.append(tx.clone()).unwrap();
        drop(journal);
        let valid_len = fs::metadata(&path).unwrap().len();
        let mut file = OpenOptions::new().append(true).open(&path).unwrap();
        file.write_all(b"{\"torn\":").unwrap();
        file.sync_all().unwrap();
        drop(file);

        let reopened = DurableTxJournal::open(path.clone()).unwrap();
        assert_eq!(
            reopened.get(tx.tx_id).unwrap().state,
            TxState::ParticipantPrepared
        );
        assert_eq!(fs::metadata(&path).unwrap().len(), valid_len);
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_rejects_commit_decision_rollback_to_abort() {
        let path = std::env::temp_dir().join(format!("hacash-l2-2pc-{}.jsonl", Uuid::new_v4()));
        let journal = DurableTxJournal::open(path.clone()).unwrap();
        let mut tx = transaction(TxState::ParticipantPrepared);
        journal.append(tx.clone()).unwrap();
        tx.state = TxState::ParticipantCommitDecided;
        journal.append(tx.clone()).unwrap();
        tx.state = TxState::ParticipantAborted;
        let error = journal.append(tx.clone()).unwrap_err();
        assert!(error.contains("state transition"), "{error}");
        assert_eq!(
            journal.get(tx.tx_id).unwrap().state,
            TxState::ParticipantCommitDecided
        );
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn journal_hash_replay_tolerates_future_defaulted_fields() {
        let path = std::env::temp_dir().join(format!("hacash-l2-2pc-{}.jsonl", Uuid::new_v4()));
        let tx = transaction(TxState::ParticipantPrepared);
        let mut raw_core = serde_json::to_value(JournalCore {
            version: JOURNAL_VERSION,
            sequence: 1,
            prev_hash_hex: String::new(),
            transaction: tx.clone(),
        })
        .unwrap();
        raw_core
            .get_mut("transaction")
            .and_then(serde_json::Value::as_object_mut)
            .unwrap()
            .remove("last_error");
        let record_hash_hex = hash_serializable(&raw_core).unwrap();
        let record = serde_json::json!({
            "core": raw_core,
            "record_hash_hex": record_hash_hex,
        });
        let mut bytes = serde_json::to_vec(&record).unwrap();
        bytes.push(b'\n');
        let mut file = File::create(&path).unwrap();
        file.write_all(&bytes).unwrap();
        file.sync_all().unwrap();
        drop(file);

        let journal = DurableTxJournal::open(path.clone()).unwrap();
        assert_eq!(
            journal.get(tx.tx_id).unwrap().state,
            TxState::ParticipantPrepared
        );
        fs::remove_file(path).unwrap();
    }

    #[tokio::test]
    async fn participant_requires_user_signatures_and_commits_exactly_once() {
        let payer = crate::hacash_keys::Account::create_by_password("2pc-payer").unwrap();
        let payee = crate::hacash_keys::Account::create_by_password("2pc-payee").unwrap();
        let hub_a_identity = crate::hacash_keys::Account::create_by_password("2pc-hub-a").unwrap();
        let hub_b_identity = crate::hacash_keys::Account::create_by_password("2pc-hub-b").unwrap();
        let channel_id = "73".repeat(16);
        let state_b = HubState::new("HubB".into(), 64, 8);
        state_b
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: payer.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();

        let meta_a = crate::types::HubMeta {
            protocol_version: "2.0".into(),
            features: vec!["distributed-2pc".into()],
            ..Default::default()
        };
        let net_a = NetClient::with_identity(
            "HubA".into(),
            "http://127.0.0.1:19090".into(),
            "Hub A".into(),
            meta_a,
            true,
            Some(hub_a_identity),
            600,
            true,
        );
        let meta_b = crate::types::HubMeta {
            protocol_version: "2.0".into(),
            features: vec!["distributed-2pc".into()],
            ..Default::default()
        };
        let net_b = NetClient::with_identity(
            "HubB".into(),
            "http://127.0.0.1:19091".into(),
            "Hub B".into(),
            meta_b,
            true,
            Some(hub_b_identity),
            600,
            true,
        );
        let hello_a = net_a.hello_payload(Vec::new(), Vec::new());
        net_b.validate_inbound_hello(&hello_a).unwrap();
        state_b.upsert_peer_from_hello(&hello_a, true).unwrap();

        let tx_id = Uuid::new_v4();
        let created_unix = now_unix();
        let payment = PaymentCommit {
            session_id: tx_id.to_string(),
            provider_id: "HubA".into(),
            payer: payer.readable().into(),
            payee: payee.readable().into(),
            amount_hac: "1:248".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: vec![channel_id.clone()],
            required_signers: vec![payee.readable().into(), payer.readable().into()],
            created_unix,
        };
        let descriptor = TxDescriptor {
            tx_id,
            coordinator_provider_id: "HubA".into(),
            coordinator_public_url: "http://127.0.0.1:19090".into(),
            participant_provider_id: "HubB".into(),
            payment_hash_hex: crate::crypto::message_hash_hex(&payment),
            payment,
            amount_zhu: crate::amounts::parse_zhu("1:248").unwrap(),
            amount_satoshi: 0,
            expires_unix: now_unix() + 300,
            hops: vec![ReservedHop {
                channel_id: channel_id.clone(),
                from_address: payer.readable().into(),
                to_address: payee.readable().into(),
            }],
        };
        let base_path =
            std::env::temp_dir().join(format!("hacash-l2-2pc-state-{}.json", Uuid::new_v4()));
        let journal_path = PathBuf::from(format!("{}.txlog", base_path.display()));
        let manager = DistributedTxManager::open(Some(&base_path)).unwrap();

        let prepare = signed_request(&net_a, TxPhase::Prepare, descriptor.clone(), &[]).unwrap();
        let prepared = manager
            .handle_participant_request(&state_b, &net_b, prepare)
            .await
            .unwrap();
        assert_eq!(prepared.state, TxState::ParticipantPrepared);

        let hash = crate::crypto::message_hash(&descriptor.payment);
        let payee_signature = PaymentSignature {
            address: payee.readable().into(),
            signature_hex: crate::crypto::sign_payment_hash(&payee, &hash),
            public_key_hex: String::new(),
            signed_unix: now_unix(),
            order_index: 0,
            verified: true,
        };
        let incomplete_commit = signed_request(
            &net_a,
            TxPhase::Commit,
            descriptor.clone(),
            std::slice::from_ref(&payee_signature),
        )
        .unwrap();
        assert!(manager
            .handle_participant_request(&state_b, &net_b, incomplete_commit)
            .await
            .unwrap_err()
            .contains("every required"));
        assert_eq!(state_b.get_channel(&channel_id).unwrap().left_hac, "2:248");

        let payer_signature = PaymentSignature {
            address: payer.readable().into(),
            signature_hex: crate::crypto::sign_payment_hash(&payer, &hash),
            public_key_hex: String::new(),
            signed_unix: now_unix(),
            order_index: 1,
            verified: true,
        };
        let commit_signatures = vec![payee_signature, payer_signature];
        let commit = signed_request(
            &net_a,
            TxPhase::Commit,
            descriptor.clone(),
            &commit_signatures,
        )
        .unwrap();
        let committed = manager
            .handle_participant_request(&state_b, &net_b, commit.clone())
            .await
            .unwrap();
        assert_eq!(committed.state, TxState::ParticipantCommitted);
        assert_eq!(state_b.get_channel(&channel_id).unwrap().left_hac, "1:248");
        let replayed = manager
            .handle_participant_request(&state_b, &net_b, commit)
            .await
            .unwrap();
        assert_eq!(replayed.state, TxState::ParticipantCommitted);
        assert_eq!(state_b.get_channel(&channel_id).unwrap().left_hac, "1:248");

        drop(manager);
        fs::remove_file(journal_path).unwrap();
    }

    #[tokio::test]
    async fn two_hubs_retry_lost_commit_ack_without_double_settlement() {
        let payer = crate::hacash_keys::Account::create_by_password("http-2pc-payer").unwrap();
        let intermediary =
            crate::hacash_keys::Account::create_by_password("http-2pc-intermediary").unwrap();
        let payee = crate::hacash_keys::Account::create_by_password("http-2pc-payee").unwrap();
        let hub_a_identity =
            crate::hacash_keys::Account::create_by_password("http-2pc-hub-a").unwrap();
        let hub_b_identity =
            crate::hacash_keys::Account::create_by_password("http-2pc-hub-b").unwrap();
        let local_channel_id = "91".repeat(16);
        let remote_channel_id = "92".repeat(16);

        let hub_a = Arc::new(HubState::new("HubA".into(), 64, 8));
        let hub_b = Arc::new(HubState::new("HubB".into(), 64, 8));
        hub_a
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: local_channel_id.clone(),
                left_address: payer.readable().into(),
                right_address: intermediary.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        hub_b
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: remote_channel_id.clone(),
                left_address: intermediary.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let participant_url = format!("http://{}", listener.local_addr().unwrap());
        let distributed_meta = crate::types::HubMeta {
            protocol_version: "2.0".into(),
            features: vec!["distributed-2pc".into()],
            ..Default::default()
        };
        let net_a = NetClient::with_identity(
            "HubA".into(),
            "http://127.0.0.1:19090".into(),
            "Hub A".into(),
            distributed_meta.clone(),
            true,
            Some(hub_a_identity),
            600,
            true,
        );
        let net_b = NetClient::with_identity(
            "HubB".into(),
            participant_url,
            "Hub B".into(),
            distributed_meta,
            true,
            Some(hub_b_identity),
            600,
            true,
        );

        let hello_a = net_a.hello_payload(hub_a.advertise_channels(), Vec::new());
        net_b.validate_inbound_hello(&hello_a).unwrap();
        hub_b.upsert_peer_from_hello(&hello_a, true).unwrap();
        let hello_b = net_b.hello_payload(hub_b.advertise_channels(), Vec::new());
        net_a.validate_inbound_hello(&hello_b).unwrap();
        hub_a.upsert_peer_from_hello(&hello_b, true).unwrap();

        let origin_base =
            std::env::temp_dir().join(format!("hacash-l2-http-2pc-origin-{}.json", Uuid::new_v4()));
        let participant_base = std::env::temp_dir().join(format!(
            "hacash-l2-http-2pc-participant-{}.json",
            Uuid::new_v4()
        ));
        let origin_journal = PathBuf::from(format!("{}.txlog", origin_base.display()));
        let participant_journal = PathBuf::from(format!("{}.txlog", participant_base.display()));
        let origin_manager = DistributedTxManager::open(Some(&origin_base)).unwrap();
        let participant_manager =
            Arc::new(DistributedTxManager::open(Some(&participant_base)).unwrap());
        let lose_first_commit_ack = Arc::new(AtomicBool::new(true));
        let commit_requests = Arc::new(AtomicUsize::new(0));
        let lose_first_abort_ack = Arc::new(AtomicBool::new(true));
        let abort_requests = Arc::new(AtomicUsize::new(0));
        let server_state = TestParticipantHttp {
            hub: hub_b.clone(),
            net: net_b.clone(),
            manager: participant_manager.clone(),
            lose_first_commit_ack: lose_first_commit_ack.clone(),
            commit_requests: commit_requests.clone(),
            lose_first_abort_ack: lose_first_abort_ack.clone(),
            abort_requests: abort_requests.clone(),
        };
        let app = Router::new()
            .route("/v1/net/tx/prepare", post(participant_http_phase))
            .route("/v1/net/tx/commit", post(participant_http_phase))
            .route("/v1/net/tx/abort", post(participant_http_phase))
            .with_state(server_state);
        let server = tokio::spawn(async move {
            axum::serve(listener, app).await.unwrap();
        });

        let payment = hub_a
            .create_distributed_payment(crate::types::CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "1:248".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![local_channel_id.clone(), remote_channel_id.clone()],
                local_only: false,
            })
            .unwrap();
        assert_eq!(payment.remote_hops.len(), 1);
        assert_eq!(
            payment.required_signers,
            vec![
                payee.readable().to_string(),
                intermediary.readable().to_string(),
                payer.readable().to_string(),
            ]
        );

        origin_manager
            .prepare_origin(&hub_a, &net_a, &payment)
            .await
            .unwrap();
        assert_eq!(
            origin_manager.transaction(payment.id).unwrap().state,
            TxState::CoordinatorPrepared
        );
        assert_eq!(
            participant_manager.transaction(payment.id).unwrap().state,
            TxState::ParticipantPrepared
        );
        assert!(hub_b.payment_reservation(payment.id).is_some());

        hub_a
            .add_signature(payment.id, payment_signature_request(&payee, &payment))
            .unwrap();
        hub_a
            .add_signature(
                payment.id,
                payment_signature_request(&intermediary, &payment),
            )
            .unwrap();
        let ready = hub_a
            .add_signature(payment.id, payment_signature_request(&payer, &payment))
            .unwrap();
        assert_eq!(ready.status, PaymentStatus::Committing);

        let awaiting_ack = origin_manager
            .commit_origin_if_ready(&hub_a, &net_a, &ready)
            .await
            .unwrap();
        assert_eq!(awaiting_ack.status, PaymentStatus::Committing);
        let pending = origin_manager.transaction(payment.id).unwrap();
        assert_eq!(pending.state, TxState::CoordinatorCommitDecided);
        assert!(!pending.participants[0].committed);
        assert_eq!(
            participant_manager.transaction(payment.id).unwrap().state,
            TxState::ParticipantCommitted
        );
        assert_eq!(
            hub_a.get_channel(&local_channel_id).unwrap().left_hac,
            "1:248"
        );
        assert_eq!(
            hub_b.get_channel(&remote_channel_id).unwrap().left_hac,
            "1:248"
        );

        assert_eq!(origin_manager.retry_pending(&hub_a, &net_a).await, 1);
        assert_eq!(
            hub_a.get_payment(payment.id).unwrap().status,
            PaymentStatus::Settled
        );
        assert_eq!(
            origin_manager.transaction(payment.id).unwrap().state,
            TxState::CoordinatorCommitted
        );
        assert_eq!(
            participant_manager.transaction(payment.id).unwrap().state,
            TxState::ParticipantCommitted
        );
        assert_eq!(commit_requests.load(Ordering::SeqCst), 2);
        assert_eq!(
            hub_a.get_channel(&local_channel_id).unwrap().left_hac,
            "1:248"
        );
        assert_eq!(
            hub_b.get_channel(&remote_channel_id).unwrap().left_hac,
            "1:248"
        );
        assert_eq!(origin_manager.retry_pending(&hub_a, &net_a).await, 0);
        assert_eq!(commit_requests.load(Ordering::SeqCst), 2);

        let abort_payment = hub_a
            .create_distributed_payment(crate::types::CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "1:248".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![local_channel_id.clone(), remote_channel_id.clone()],
                local_only: false,
            })
            .unwrap();
        origin_manager
            .prepare_origin(&hub_a, &net_a, &abort_payment)
            .await
            .unwrap();
        let abort_pending = origin_manager
            .abort_origin(
                &hub_a,
                &net_a,
                abort_payment.id,
                "test cancellation before commit decision",
            )
            .await
            .unwrap();
        assert_eq!(abort_pending.status, PaymentStatus::Failed);
        let pending_abort = origin_manager.transaction(abort_payment.id).unwrap();
        assert_eq!(pending_abort.state, TxState::CoordinatorAbortDecided);
        assert!(!pending_abort.participants[0].aborted);
        assert_eq!(
            participant_manager
                .transaction(abort_payment.id)
                .unwrap()
                .state,
            TxState::ParticipantAborted
        );
        assert!(hub_a.payment_reservation(abort_payment.id).is_none());
        assert!(hub_b.payment_reservation(abort_payment.id).is_none());
        assert_eq!(
            hub_a.get_channel(&local_channel_id).unwrap().left_hac,
            "1:248"
        );
        assert_eq!(
            hub_b.get_channel(&remote_channel_id).unwrap().left_hac,
            "1:248"
        );

        assert_eq!(origin_manager.retry_pending(&hub_a, &net_a).await, 1);
        let completed_abort = origin_manager.transaction(abort_payment.id).unwrap();
        assert_eq!(completed_abort.state, TxState::CoordinatorAborted);
        assert!(completed_abort.participants[0].aborted);
        assert_eq!(abort_requests.load(Ordering::SeqCst), 2);
        assert_eq!(origin_manager.retry_pending(&hub_a, &net_a).await, 0);
        assert_eq!(abort_requests.load(Ordering::SeqCst), 2);
        assert_eq!(
            hub_a.get_channel(&local_channel_id).unwrap().left_hac,
            "1:248"
        );
        assert_eq!(
            hub_b.get_channel(&remote_channel_id).unwrap().left_hac,
            "1:248"
        );

        server.abort();
        let _ = server.await;
        drop(participant_manager);
        drop(origin_manager);
        fs::remove_file(origin_journal).unwrap();
        fs::remove_file(participant_journal).unwrap();
    }

    #[tokio::test]
    async fn recovery_replays_durable_commit_decision_exactly_once() {
        let payer = crate::hacash_keys::Account::create_by_password("recover-payer").unwrap();
        let payee = crate::hacash_keys::Account::create_by_password("recover-payee").unwrap();
        let channel_id = "84".repeat(16);
        let tx_id = Uuid::new_v4();
        let base_path = std::env::temp_dir().join(format!("hacash-l2-2pc-recover-{tx_id}.json"));
        let journal_path = PathBuf::from(format!("{}.txlog", base_path.display()));
        let manager = DistributedTxManager::open(Some(&base_path)).unwrap();
        let hop = ReservedHop {
            channel_id: channel_id.clone(),
            from_address: payer.readable().into(),
            to_address: payee.readable().into(),
        };
        let mut transaction = DistributedTransaction {
            tx_id,
            role: TxRole::Participant,
            state: TxState::ParticipantPrepared,
            coordinator_provider_id: "HubA".into(),
            coordinator_public_url: "http://127.0.0.1:19090".into(),
            payment_hash_hex: "42".repeat(32),
            amount_zhu: crate::amounts::parse_zhu("1:248").unwrap(),
            amount_satoshi: 0,
            expires_unix: now_unix() + 300,
            local_hops: vec![hop],
            participants: Vec::new(),
            coordinator_payment: None,
            origin_idempotency: None,
            created_unix: now_unix(),
            updated_unix: now_unix(),
            last_error: String::new(),
        };
        manager.append(transaction.clone()).await.unwrap();
        transaction.state = TxState::ParticipantCommitDecided;
        manager.append(transaction).await.unwrap();
        drop(manager);

        let restored_manager = DistributedTxManager::open(Some(&base_path)).unwrap();
        let restored_state = HubState::new("HubB".into(), 64, 8);
        restored_state
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: payer.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        restored_manager.recover_local(&restored_state).unwrap();
        assert_eq!(
            restored_state.get_channel(&channel_id).unwrap().left_hac,
            "1:248"
        );
        restored_manager.recover_local(&restored_state).unwrap();
        assert_eq!(
            restored_state.get_channel(&channel_id).unwrap().left_hac,
            "1:248"
        );
        drop(restored_manager);
        fs::remove_file(journal_path).unwrap();
    }
}
#[cfg(test)]
mod idempotency_recovery_test {
    use super::*;
    #[tokio::test]
    async fn coordinator_recovery_restores_missing_idempotency_mapping() {
        let payer = crate::hacash_keys::Account::create_by_password("recover-idem-payer").unwrap();
        let payee = crate::hacash_keys::Account::create_by_password("recover-idem-payee").unwrap();
        let channel_id = "85".repeat(16);
        let request = crate::types::CreatePaymentRequest {
            payer: payer.readable().into(),
            payee: payee.readable().into(),
            amount_hac: "1:248".into(),
            amount_satoshi: 0,
            fee_hac: "0".into(),
            route: Vec::new(),
            local_only: true,
        };
        let origin = HubState::new("HubA".into(), 64, 8);
        origin
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: payer.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let (mut payment, replayed) = origin
            .create_distributed_payment_idempotent(
                request.clone(),
                "recover-request",
                payer.readable(),
            )
            .unwrap();
        assert!(!replayed);
        payment.remote_hops.push(crate::types::RemoteHop {
            channel_id: "86".repeat(16),
            via_provider: "HubB".into(),
            public_url: Some("http://127.0.0.1:19091".into()),
            from_address: payer.readable().into(),
            to_address: payee.readable().into(),
        });
        let reservation = origin.payment_reservation(payment.id).unwrap();
        let origin_idempotency = origin.idempotency_for_payment(payment.id).unwrap();
        let base_path =
            std::env::temp_dir().join(format!("hacash-l2-2pc-idem-{}.json", payment.id));
        let journal_path = PathBuf::from(format!("{}.txlog", base_path.display()));
        let manager = DistributedTxManager::open(Some(&base_path)).unwrap();
        let now = now_unix();
        let mut transaction = DistributedTransaction {
            tx_id: payment.id,
            role: TxRole::Coordinator,
            state: TxState::CoordinatorPreparing,
            coordinator_provider_id: "HubA".into(),
            coordinator_public_url: "http://127.0.0.1:19090".into(),
            payment_hash_hex: payment.message_hash_hex.clone(),
            amount_zhu: crate::amounts::parse_zhu(&payment.amount_hac).unwrap(),
            amount_satoshi: payment.amount_satoshi,
            expires_unix: payment.expires_unix,
            local_hops: reservation.hops,
            participants: Vec::new(),
            coordinator_payment: Some(payment.clone()),
            origin_idempotency: Some(origin_idempotency),
            created_unix: now,
            updated_unix: now,
            last_error: String::new(),
        };
        manager.append(transaction.clone()).await.unwrap();
        transaction.state = TxState::CoordinatorPrepared;
        manager.append(transaction).await.unwrap();

        let restored = HubState::new("HubA".into(), 64, 8);
        restored
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id,
                left_address: payer.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        restored
            .restore_distributed_payment(payment.clone())
            .unwrap();
        assert!(restored.idempotency_for_payment(payment.id).is_none());
        manager.recover_local(&restored).unwrap();
        let (same_payment, replayed) = restored
            .create_distributed_payment_idempotent(request, "recover-request", payer.readable())
            .unwrap();
        assert!(replayed);
        assert_eq!(same_payment.id, payment.id);
        drop(manager);
        fs::remove_file(journal_path).unwrap();
    }

    #[tokio::test]
    async fn commit_decision_image_replaces_a_stale_payment_snapshot() {
        let payer =
            crate::hacash_keys::Account::create_by_password("stale-snapshot-payer").unwrap();
        let payee =
            crate::hacash_keys::Account::create_by_password("stale-snapshot-payee").unwrap();
        let channel_id = "87".repeat(16);
        let origin = HubState::new("HubA".into(), 64, 8);
        origin
            .register_channel(crate::types::RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: payer.readable().into(),
                right_address: payee.readable().into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let stale = origin
            .create_distributed_payment(crate::types::CreatePaymentRequest {
                payer: payer.readable().into(),
                payee: payee.readable().into(),
                amount_hac: "1:248".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![channel_id],
                local_only: true,
            })
            .unwrap();
        let reservation = origin.payment_reservation(stale.id).unwrap();
        let mut decided = stale.clone();
        decided.remote_hops.push(crate::types::RemoteHop {
            channel_id: "88".repeat(16),
            via_provider: "HubB".into(),
            public_url: Some("http://127.0.0.1:19091".into()),
            from_address: payer.readable().into(),
            to_address: payee.readable().into(),
        });
        let hash_bytes = hex::decode(&decided.message_hash_hex).unwrap();
        let hash: [u8; 32] = hash_bytes.try_into().unwrap();
        decided.signatures = vec![
            PaymentSignature {
                address: payee.readable().into(),
                signature_hex: crate::crypto::sign_payment_hash(&payee, &hash),
                public_key_hex: String::new(),
                signed_unix: now_unix(),
                order_index: 0,
                verified: true,
            },
            PaymentSignature {
                address: payer.readable().into(),
                signature_hex: crate::crypto::sign_payment_hash(&payer, &hash),
                public_key_hex: String::new(),
                signed_unix: now_unix(),
                order_index: 1,
                verified: true,
            },
        ];
        decided.status = PaymentStatus::Committing;

        let base_path = std::env::temp_dir().join(format!("hacash-l2-stale-{}.json", stale.id));
        let journal_path = PathBuf::from(format!("{}.txlog", base_path.display()));
        let manager = DistributedTxManager::open(Some(&base_path)).unwrap();
        let now = now_unix();
        let mut transaction = DistributedTransaction {
            tx_id: stale.id,
            role: TxRole::Coordinator,
            state: TxState::CoordinatorPreparing,
            coordinator_provider_id: "HubA".into(),
            coordinator_public_url: "http://127.0.0.1:19090".into(),
            payment_hash_hex: stale.message_hash_hex.clone(),
            amount_zhu: crate::amounts::parse_zhu(&stale.amount_hac).unwrap(),
            amount_satoshi: 0,
            expires_unix: stale.expires_unix,
            local_hops: reservation.hops,
            participants: Vec::new(),
            coordinator_payment: Some(stale.clone()),
            origin_idempotency: None,
            created_unix: now,
            updated_unix: now,
            last_error: String::new(),
        };
        manager.append(transaction.clone()).await.unwrap();
        transaction.state = TxState::CoordinatorPrepared;
        manager.append(transaction.clone()).await.unwrap();
        transaction.state = TxState::CoordinatorCommitDecided;
        transaction.coordinator_payment = Some(decided);
        manager.append(transaction).await.unwrap();

        manager.recover_local(&origin).unwrap();
        let recovered = origin.get_payment(stale.id).unwrap();
        assert_eq!(recovered.status, PaymentStatus::Committing);
        assert_eq!(recovered.signatures.len(), 2);
        assert!(recovered
            .remote_hops
            .iter()
            .any(|hop| hop.via_provider == "HubB"));
        assert_eq!(
            origin
                .get_channel("87878787878787878787878787878787")
                .unwrap()
                .left_hac,
            "1:248"
        );

        drop(manager);
        fs::remove_file(journal_path).unwrap();
    }
}
fn validate_participant_coverage(hub: &HubState, descriptor: &TxDescriptor) -> Result<(), String> {
    let described: std::collections::HashSet<&str> = descriptor
        .hops
        .iter()
        .map(|hop| hop.channel_id.as_str())
        .collect();
    for hop in &descriptor.hops {
        if hub.get_channel(&hop.channel_id).is_none() {
            return Err(format!(
                "participant does not own described channel {}",
                hop.channel_id
            ));
        }
    }
    let locally_owned: std::collections::HashSet<&str> = descriptor
        .payment
        .route
        .iter()
        .filter(|channel_id| hub.get_channel(channel_id).is_some())
        .map(String::as_str)
        .collect();
    if locally_owned != described {
        return Err(
            "participant descriptor does not exactly cover its channels in the signed route".into(),
        );
    }
    Ok(())
}
