//! Optional JSON persistence for channels + peer seeds + last bills + agent recovery.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use tracing::{info, warn};

use crate::channel_state::ChannelEquivocationProofV2;
use crate::channel_state_store::{ChannelActivationRecordV1, ChannelStateObservationV2};
use crate::state::{AgentPersistSnapshot, HubState};
use crate::types::{ChannelBill, LocalChannel, PeerHub, PeerSeed, RegisterChannelRequest};

const PERSIST_VERSION: u32 = 9;

#[derive(Debug, Clone, Serialize, Deserialize)]
struct PersistFile {
    version: u32,
    provider_id: String,
    channels: Vec<LocalChannel>,
    peers: Vec<PeerSeed>,
    /// Phase C: last bill per channel only.
    #[serde(default)]
    bills: Vec<ChannelBill>,
    /// v6: verified hub identity pins required for authenticated 2PC recovery.
    #[serde(default)]
    trusted_peers: Vec<PeerHub>,
    /// v3: open payments, invoices, identities, idempotency (agent recovery).
    #[serde(default)]
    agent: AgentPersistSnapshot,
    /// v7: verified V2 shadow observations, bounded to latest state per party.
    #[serde(default)]
    channel_state_observations_v2: Vec<ChannelStateObservationV2>,
    /// v7: portable, cryptographically verified equivocation evidence.
    #[serde(default)]
    channel_state_proofs_v2: Vec<ChannelEquivocationProofV2>,
    /// v9: permanent, mutually signed opt-in plus the latest verified chain head.
    #[serde(default)]
    channel_activations_v1: Vec<ChannelActivationRecordV1>,
}

/// Load channels/peers/bills/agent state from `path` into state. Missing file = ok.
pub fn load_into(state: &HubState, path: &Path, provider_id: &str) -> Result<usize, String> {
    let backup = backup_path(path);
    if !path.exists() && !backup.exists() {
        return Ok(0);
    }
    let load_file = |candidate: &Path| -> Result<PersistFile, String> {
        let raw = fs::read_to_string(candidate).map_err(|e| format!("read {candidate:?}: {e}"))?;
        serde_json::from_str(&raw).map_err(|e| format!("parse persist JSON {candidate:?}: {e}"))
    };
    let (file, loaded_path) = match load_file(path) {
        Ok(file) => (file, path.to_path_buf()),
        Err(primary_error) if backup.exists() => {
            warn!(error = %primary_error, backup = %backup.display(), "primary persist snapshot invalid; recovering backup");
            (load_file(&backup)?, backup)
        }
        Err(error) => return Err(error),
    };
    if file.version > PERSIST_VERSION {
        return Err(format!(
            "persist snapshot version {} is newer than supported version {}; refusing unsafe downgrade",
            file.version, PERSIST_VERSION
        ));
    }
    if !file.provider_id.is_empty() && file.provider_id != provider_id {
        warn!(
            file_provider = %file.provider_id,
            this_provider = %provider_id,
            "persist provider_id differs; still loading channels"
        );
    }
    let mut n = 0usize;
    for ch in file.channels {
        let id = ch.channel_id.clone();
        let l1_status = ch.l1_status;
        let open_height = ch.open_height;
        let l1_anchor = ch.l1_anchor.clone();
        let registered_unix = ch.registered_unix;
        let balance_source = ch.balance_source.clone();
        let last_settle_payment_id = ch.last_settle_payment_id;
        match state.register_channel(RegisterChannelRequest {
            channel_id: ch.channel_id,
            left_address: ch.left_address,
            right_address: ch.right_address,
            left_hac: ch.left_hac,
            right_hac: ch.right_hac,
            left_satoshi: ch.left_satoshi,
            right_satoshi: ch.right_satoshi,
            hub_side: Some(ch.hub_side),
            notes: ch.notes,
        }) {
            Ok(_) => {
                n += 1;
                if l1_status.is_some() || open_height.is_some() {
                    let _ = state.update_channel_l1(&id, l1_status, open_height);
                }
                if let Err(error) = state.restore_channel_persist_metadata(
                    &id,
                    registered_unix,
                    &balance_source,
                    last_settle_payment_id,
                ) {
                    warn!(%error, channel = %id, "channel settlement metadata not restored");
                }
                if let Some(anchor) = l1_anchor {
                    state.restore_channel_l1_anchor(&id, anchor)?;
                }
            }
            Err(e) => warn!(error = %e, channel = %id, "skip bad channel from persist"),
        }
    }

    for peer in file.trusted_peers {
        if let Err(error) = state.restore_trusted_peer(peer) {
            warn!(%error, "skip invalid persisted trusted peer");
        }
    }
    let mut bills_n = 0usize;
    for bill in file.bills {
        match state.restore_bill(bill) {
            Ok(()) => bills_n += 1,
            Err(e) => warn!(error = %e, "skip bad bill from persist"),
        }
    }

    let channel_state_observations_n = file.channel_state_observations_v2.len();
    for observation in file.channel_state_observations_v2 {
        state.restore_channel_state_observation_v2(observation)?;
    }
    let channel_state_proofs_n = file.channel_state_proofs_v2.len();
    for proof in file.channel_state_proofs_v2 {
        state.restore_channel_state_proof_v2(proof)?;
    }
    let channel_activations_n = file.channel_activations_v1.len();
    for activation in file.channel_activations_v1 {
        state.restore_channel_activation_v1(activation)?;
    }
    let peer_n = file.peers.len();
    for p in &file.peers {
        let _ = state.remember_seed(&p.provider_id, &p.public_url);
    }

    let agent_payments = file.agent.payments.len();
    let agent_inv = file.agent.invoices.len();
    if let Err(e) = state.import_agent_persist(file.agent) {
        warn!(error = %e, "agent persist import failed");
    }

    info!(
        channels = n,
        peers = peer_n,
        bills = bills_n,
        channel_state_observations = channel_state_observations_n,
        channel_state_proofs = channel_state_proofs_n,
        channel_activations = channel_activations_n,
        agent_payments,
        agent_invoices = agent_inv,
        path = %loaded_path.display(),
        "loaded hub state"
    );
    Ok(n)
}

pub fn save_from(state: &HubState, path: &Path, provider_id: &str) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent).map_err(|e| format!("mkdir {parent:?}: {e}"))?;
        }
    }
    // Capture channels, bills and agent settlement state under one read lock.
    let bundle = state.export_persist_bundle();
    let channels = bundle.channels;
    let peers = bundle.peers;
    let bills = bundle.bills;
    let trusted_peers = bundle.trusted_peers;
    let agent = bundle.agent;
    let channel_state_observations_v2 = bundle.channel_state_observations_v2;
    let channel_state_proofs_v2 = bundle.channel_state_proofs_v2;
    let channel_activations_v1 = bundle.channel_activations_v1;
    let file = PersistFile {
        version: PERSIST_VERSION,
        provider_id: provider_id.to_string(),
        channels,
        peers,
        bills,
        trusted_peers,
        agent,
        channel_state_observations_v2,
        channel_state_proofs_v2,
        channel_activations_v1,
    };
    let tmp = temp_path(path);
    let json = serde_json::to_string_pretty(&file).map_err(|e| e.to_string())?;
    let mut options = fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut output = options
        .open(&tmp)
        .map_err(|e| format!("open temporary persist snapshot {tmp:?}: {e}"))?;
    output
        .write_all(json.as_bytes())
        .map_err(|e| format!("write temporary persist snapshot {tmp:?}: {e}"))?;
    output
        .sync_all()
        .map_err(|e| format!("sync temporary persist snapshot {tmp:?}: {e}"))?;
    drop(output);

    replace_snapshot(&tmp, path)?;
    sync_parent(path);
    Ok(())
}

fn temp_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.tmp", path.display()))
}

fn backup_path(path: &Path) -> PathBuf {
    PathBuf::from(format!("{}.bak", path.display()))
}

#[cfg(not(windows))]
fn replace_snapshot(tmp: &Path, path: &Path) -> Result<(), String> {
    fs::rename(tmp, path).map_err(|e| format!("atomically replace persist snapshot {path:?}: {e}"))
}

#[cfg(windows)]
fn replace_snapshot(tmp: &Path, path: &Path) -> Result<(), String> {
    let backup = backup_path(path);
    if backup.exists() {
        fs::remove_file(&backup)
            .map_err(|e| format!("remove stale persist backup {backup:?}: {e}"))?;
    }
    if path.exists() {
        fs::rename(path, &backup)
            .map_err(|e| format!("rotate persist snapshot to {backup:?}: {e}"))?;
    }
    if let Err(error) = fs::rename(tmp, path) {
        if backup.exists() {
            let _ = fs::rename(&backup, path);
        }
        return Err(format!("activate persist snapshot {path:?}: {error}"));
    }
    if backup.exists() {
        fs::remove_file(&backup).map_err(|e| format!("remove persist backup {backup:?}: {e}"))?;
    }
    Ok(())
}

#[cfg(unix)]
fn sync_parent(path: &Path) {
    if let Some(parent) = path.parent() {
        if let Ok(directory) = fs::File::open(parent) {
            let _ = directory.sync_all();
        }
    }
}

#[cfg(not(unix))]
fn sync_parent(_path: &Path) {}

/// Background: periodically flush state to disk.
pub async fn persist_loop(
    state: std::sync::Arc<HubState>,
    path: PathBuf,
    provider_id: String,
    interval_secs: u64,
    persist_lock: std::sync::Arc<tokio::sync::Mutex<()>>,
) {
    let mut tick = tokio::time::interval(std::time::Duration::from_secs(interval_secs.max(5)));
    loop {
        tick.tick().await;
        let _guard = persist_lock.lock().await;
        let state_for_save = state.clone();
        let path_for_save = path.clone();
        let provider_for_save = provider_id.clone();
        match tokio::task::spawn_blocking(move || {
            save_from(&state_for_save, &path_for_save, &provider_for_save)
        })
        .await
        {
            Ok(Ok(())) => {}
            Ok(Err(error)) => warn!(%error, "persist save failed"),
            Err(error) => warn!(%error, "persist save worker failed"),
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_save_replaces_snapshot_and_backup_recovers_corruption() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-persist-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let state = HubState::new("HubPersist".into(), 32, 8);

        save_from(&state, &path, "HubPersist").unwrap();
        // Regression for Windows: rename must replace an existing snapshot.
        save_from(&state, &path, "HubPersist").unwrap();
        assert!(path.exists());

        fs::copy(&path, &backup).unwrap();
        fs::write(&path, b"{truncated").unwrap();
        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }

    #[test]
    fn reservation_survives_checkpoint_and_still_prevents_double_spend() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-reservation-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: "44".repeat(16),
                left_address: "payer".into(),
                right_address: "payee".into(),
                left_hac: "1:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        state
            .create_payment(crate::types::CreatePaymentRequest {
                payer: "payer".into(),
                payee: "payee".into(),
                amount_hac: "75:246".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap();
        let stream = state
            .open_micro_stream(crate::micro::OpenMicroRequest {
                payer: "payer".into(),
                payee: "payee".into(),
                max_hac_zhu: 25_000_000,
                max_hac_mei: 0,
                max_satoshi: 0,
                create_payments: false,
                local_only: true,
                agent_id: "agent-persist".into(),
                meta: crate::agent_pay::AgentPaymentMeta::default(),
            })
            .unwrap();
        let identity_account =
            crate::hacash_keys::Account::create_by_password("persisted-revocation").unwrap();
        state
            .register_identity(crate::agent_id::RegisterIdentityRequest {
                agent_id: "revoked-agent".into(),
                public_key_hex: hex::encode(identity_account.public_key().serialize_compressed()),
                label: String::new(),
                contact: String::new(),
            })
            .unwrap();
        state
            .set_identity_scopes("revoked-agent", &["micro".into()])
            .unwrap();
        state.revoke_identity("revoked-agent").unwrap();
        save_from(&state, &path, "HubPersist").unwrap();

        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();
        assert!(restored.get_micro_stream(stream.id).is_some());
        let restored_identity = restored.get_identity("revoked-agent").unwrap();
        assert!(restored_identity.revoked);
        assert_eq!(restored_identity.scopes, vec!["micro"]);
        assert!(!restored_identity.allows("micro"));
        let error = restored
            .create_payment(crate::types::CreatePaymentRequest {
                payer: "payer".into(),
                payee: "payee".into(),
                amount_hac: "50:246".into(),
                amount_satoshi: 0,
                fee_hac: "0".into(),
                route: vec![],
                local_only: true,
            })
            .unwrap_err();
        assert!(
            error.contains("liquidity") || error.contains("reserved"),
            "{error}"
        );

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }

    #[test]
    fn distributed_settlement_marker_survives_snapshot_reload() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-marker-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let channel_id = "45".repeat(16);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: "payer".into(),
                right_address: "payee".into(),
                left_hac: "2:248".into(),
                right_hac: "0".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let transaction_id = uuid::Uuid::new_v4();
        let hop = crate::state::ReservedHop {
            channel_id: channel_id.clone(),
            from_address: "payer".into(),
            to_address: "payee".into(),
        };
        state
            .prepare_distributed_reservation(
                transaction_id,
                crate::amounts::parse_zhu("1:248").unwrap(),
                0,
                std::slice::from_ref(&hop),
                0,
            )
            .unwrap();
        state
            .apply_distributed_settlement(
                transaction_id,
                crate::amounts::parse_zhu("1:248").unwrap(),
                0,
                std::slice::from_ref(&hop),
            )
            .unwrap();
        save_from(&state, &path, "HubPersist").unwrap();

        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();
        let channel = restored.get_channel(&channel_id).unwrap();
        assert_eq!(channel.left_hac, "1:248");
        assert_eq!(channel.balance_source, "distributed_2pc_commit");
        assert_eq!(channel.last_settle_payment_id, Some(transaction_id));
        restored
            .apply_distributed_settlement(
                transaction_id,
                crate::amounts::parse_zhu("1:248").unwrap(),
                0,
                &[hop],
            )
            .unwrap();
        assert_eq!(restored.get_channel(&channel_id).unwrap().left_hac, "1:248");

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }
    #[test]
    fn channel_state_evidence_survives_snapshot_restart() {
        use crate::channel_state::{
            sign_channel_state, ChannelStateCommitmentV2, CHANNEL_STATE_SCHEMA_V2,
        };
        use crate::channel_state_store::ChannelStateObservationOutcomeV2;
        use crate::hacash_keys::Account;

        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-v2-evidence-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let left = Account::create_by_password("persist-v2-left").unwrap();
        let right = Account::create_by_password("persist-v2-right").unwrap();
        let channel_id = "ab".repeat(16);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: left.readable().to_string(),
                right_address: right.readable().to_string(),
                left_hac: "6:245".into(),
                right_hac: "4:245".into(),
                left_satoshi: 30,
                right_satoshi: 70,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let commitment = |left_zhu| ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: "11".repeat(32),
            channel_id: channel_id.clone(),
            funding_anchor_hash_hex: "33".repeat(32),
            sequence: 1,
            previous_state_hash_hex: String::new(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: left_zhu,
            right_hac_zhu: 1_000_000 - left_zhu,
            left_satoshi: 30,
            right_satoshi: 70,
            funded_hac_zhu: 1_000_000,
            funded_satoshi: 100,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        };
        let first = sign_channel_state(&left, commitment(600_000)).unwrap();
        state.observe_channel_state_v2(&channel_id, first).unwrap();
        let conflicting = sign_channel_state(&left, commitment(550_000)).unwrap();
        let result = state
            .observe_channel_state_v2(&channel_id, conflicting)
            .unwrap();
        assert_eq!(
            result.outcome,
            ChannelStateObservationOutcomeV2::Equivocation
        );
        assert_eq!(result.proof_ids.len(), 1);
        save_from(&state, &path, "HubPersist").unwrap();

        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();
        let observations = restored.channel_state_observations_v2(&channel_id).unwrap();
        assert_eq!(observations.len(), 1);
        let proofs = restored.channel_state_proofs_v2(&channel_id).unwrap();
        assert_eq!(proofs.len(), 1);
        proofs[0].1.validate().unwrap();
        assert!(restored
            .get_channel_state_proof_v2(&channel_id, &proofs[0].0)
            .unwrap()
            .is_some());

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }
    #[test]
    fn corrupted_channel_state_observation_fails_closed_on_load() {
        use crate::channel_state::{
            sign_channel_state, ChannelStateCommitmentV2, CHANNEL_STATE_SCHEMA_V2,
        };
        use crate::hacash_keys::Account;

        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-v2-corrupt-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let left = Account::create_by_password("persist-corrupt-left").unwrap();
        let right = Account::create_by_password("persist-corrupt-right").unwrap();
        let channel_id = "cd".repeat(16);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: left.readable().to_string(),
                right_address: right.readable().to_string(),
                left_hac: "6:245".into(),
                right_hac: "4:245".into(),
                left_satoshi: 0,
                right_satoshi: 0,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let commitment = ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: "11".repeat(32),
            channel_id: channel_id.clone(),
            funding_anchor_hash_hex: "33".repeat(32),
            sequence: 1,
            previous_state_hash_hex: String::new(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: 600_000,
            right_hac_zhu: 400_000,
            left_satoshi: 0,
            right_satoshi: 0,
            funded_hac_zhu: 1_000_000,
            funded_satoshi: 0,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        };
        state
            .observe_channel_state_v2(&channel_id, sign_channel_state(&left, commitment).unwrap())
            .unwrap();
        save_from(&state, &path, "HubPersist").unwrap();

        let mut snapshot: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        snapshot["channel_state_observations_v2"][0]["state"]["state_hash_hex"] =
            serde_json::Value::String("00".repeat(32));
        fs::write(&path, serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();

        let restored = HubState::new("HubPersist".into(), 32, 8);
        let error = load_into(&restored, &path, "HubPersist").unwrap_err();
        assert!(error.contains("state_hash_hex"));

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }
    #[test]
    fn l1_anchor_survives_restart_and_semantic_corruption_fails_closed() {
        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-anchor-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let channel_id = "ef".repeat(16);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: "1PersistAnchorLeft".into(),
                right_address: "1PersistAnchorRight".into(),
                left_hac: "6:245".into(),
                right_hac: "4:245".into(),
                left_satoshi: 30,
                right_satoshi: 70,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let observation = crate::l1_anchor::parse_fullnode_channel_observation(
            &channel_id,
            &serde_json::json!({
                "ret": 0,
                "id": channel_id,
                "status": 0,
                "open_height": 12345,
                "close_height": 0,
                "reuse_version": 4,
                "arbitration_lock": 5000,
                "interest_attribution": 0,
                "left": {
                    "address": "1PersistAnchorLeft",
                    "hacash": "6:245",
                    "satoshi": 30
                },
                "right": {
                    "address": "1PersistAnchorRight",
                    "hacash": "4:245",
                    "satoshi": 70
                }
            }),
            13000,
            1_700_000_000,
        )
        .unwrap();
        let expected = observation.anchor.clone();
        state
            .apply_l1_channel_observation(&channel_id, observation)
            .unwrap();
        save_from(&state, &path, "HubPersist").unwrap();

        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();
        assert_eq!(
            restored.get_channel(&channel_id).unwrap().l1_anchor,
            Some(expected)
        );

        let mut snapshot: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        snapshot["channels"][0]["l1_anchor"]["funding_incarnation_hash_hex"] =
            serde_json::Value::String("00".repeat(32));
        fs::write(&path, serde_json::to_vec_pretty(&snapshot).unwrap()).unwrap();
        let corrupted = HubState::new("HubPersist".into(), 32, 8);
        let error = load_into(&corrupted, &path, "HubPersist").unwrap_err();
        assert!(error.contains("funding_incarnation_hash_hex"), "{error}");

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }
    #[test]
    fn negotiated_activation_survives_restart_and_corruption_fails_closed() {
        use crate::channel_activation::{sign_channel_activation, SignedChannelActivationV1};
        use crate::channel_state::{
            sign_channel_state, ChannelStateCommitmentV2, CHANNEL_STATE_SCHEMA_V2,
        };
        use crate::hacash_keys::Account;

        let unique = uuid::Uuid::new_v4();
        let path = std::env::temp_dir().join(format!("hacash-l2-v2-activation-{unique}.json"));
        let backup = backup_path(&path);
        let tmp = temp_path(&path);
        let left = Account::create_by_password("persist-activation-left").unwrap();
        let right = Account::create_by_password("persist-activation-right").unwrap();
        let channel_id = "91".repeat(16);
        let state = HubState::new("HubPersist".into(), 32, 8);
        state
            .register_channel(RegisterChannelRequest {
                channel_id: channel_id.clone(),
                left_address: left.readable().to_string(),
                right_address: right.readable().to_string(),
                left_hac: "6:245".into(),
                right_hac: "4:245".into(),
                left_satoshi: 30,
                right_satoshi: 70,
                hub_side: None,
                notes: String::new(),
            })
            .unwrap();
        let observation = crate::l1_anchor::parse_fullnode_channel_observation(
            &channel_id,
            &serde_json::json!({
                "ret": 0,
                "id": channel_id,
                "status": 0,
                "open_height": 12345,
                "close_height": 0,
                "reuse_version": 2,
                "arbitration_lock": 5000,
                "interest_attribution": 0,
                "left": {
                    "address": left.readable(),
                    "hacash": "6:245",
                    "satoshi": 30
                },
                "right": {
                    "address": right.readable(),
                    "hacash": "4:245",
                    "satoshi": 70
                }
            }),
            13000,
            1_700_000_000,
        )
        .unwrap();
        let anchor = observation.anchor.clone();
        state
            .apply_l1_channel_observation(&channel_id, observation)
            .unwrap();

        let commitment = ChannelStateCommitmentV2 {
            schema_version: CHANNEL_STATE_SCHEMA_V2,
            network_genesis_hash_hex: anchor.network_genesis_hash_hex.clone(),
            channel_id: channel_id.clone(),
            funding_anchor_hash_hex: anchor.funding_incarnation_hash_hex.clone(),
            sequence: 1,
            previous_state_hash_hex: String::new(),
            left_address: left.readable().to_string(),
            right_address: right.readable().to_string(),
            left_hac_zhu: 600_000,
            right_hac_zhu: 400_000,
            left_satoshi: 30,
            right_satoshi: 70,
            funded_hac_zhu: 1_000_000,
            funded_satoshi: 100,
            conditional_state_root_hex: String::new(),
            expiry_unix: 0,
        };
        let left_state = sign_channel_state(&left, commitment.clone()).unwrap();
        let state_hash = left_state.state_hash_hex.clone();
        state
            .observe_channel_state_v2(&channel_id, left_state)
            .unwrap();
        state
            .observe_channel_state_v2(&channel_id, sign_channel_state(&right, commitment).unwrap())
            .unwrap();
        let draft = state
            .channel_activation_draft_v1(&channel_id, &state_hash)
            .unwrap();
        let mut signatures = vec![
            sign_channel_activation(&left, draft.commitment.clone()).unwrap(),
            sign_channel_activation(&right, draft.commitment.clone()).unwrap(),
        ];
        signatures.sort_by(|a, b| a.address.cmp(&b.address));
        let certificate = SignedChannelActivationV1 {
            commitment: draft.commitment,
            activation_hash_hex: draft.activation_hash_hex,
            signatures,
        };
        state.activate_channel_v2(&channel_id, certificate).unwrap();
        save_from(&state, &path, "HubPersist").unwrap();

        let valid_snapshot: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
        assert_eq!(valid_snapshot["version"], serde_json::json!(9));
        let restored = HubState::new("HubPersist".into(), 32, 8);
        load_into(&restored, &path, "HubPersist").unwrap();
        let restored_activation = restored
            .channel_activation_v1(&channel_id)
            .unwrap()
            .unwrap();
        assert_eq!(
            restored_activation.verification_head.state_hash_hex,
            state_hash
        );

        let mut legacy_snapshot = valid_snapshot.clone();
        legacy_snapshot["version"] = serde_json::json!(8);
        legacy_snapshot
            .as_object_mut()
            .unwrap()
            .remove("channel_activations_v1");
        fs::write(&path, serde_json::to_vec_pretty(&legacy_snapshot).unwrap()).unwrap();
        let legacy = HubState::new("HubPersist".into(), 32, 8);
        load_into(&legacy, &path, "HubPersist").unwrap();
        assert!(legacy.channel_activation_v1(&channel_id).unwrap().is_none());

        let mut corrupted = valid_snapshot;
        corrupted["channel_activations_v1"][0]["verification_head"]["state_hash_hex"] =
            serde_json::Value::String("00".repeat(32));
        fs::write(&path, serde_json::to_vec_pretty(&corrupted).unwrap()).unwrap();
        let rejected = HubState::new("HubPersist".into(), 32, 8);
        let error = load_into(&rejected, &path, "HubPersist").unwrap_err();
        assert!(error.contains("state_hash_hex"), "{error}");

        for candidate in [&path, &backup, &tmp] {
            if candidate.exists() {
                fs::remove_file(candidate).unwrap();
            }
        }
    }
}
