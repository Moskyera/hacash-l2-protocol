use std::fs::OpenOptions;
use std::io::Write;

use super::*;

fn payment_id(payment: &Value) -> Result<String, String> {
    payment["id"]
        .as_str()
        .map(str::to_string)
        .ok_or_else(|| "payment id missing".into())
}

async fn wait_aborted(cluster: &Cluster, payment_id: &str) -> Result<(), String> {
    cluster
        .wait_transaction_state(
            &cluster.a_spec.direct_url(),
            payment_id,
            "coordinator_aborted",
        )
        .await?;
    cluster
        .wait_transaction_state(
            &cluster.b_spec.direct_url(),
            payment_id,
            "participant_aborted",
        )
        .await?;
    cluster.wait_payment_status(payment_id, "failed").await?;
    cluster.assert_left_balances("4:248").await
}

async fn wait_committed(cluster: &Cluster, payment_id: &str, balance: &str) -> Result<(), String> {
    cluster.wait_payment_status(payment_id, "settled").await?;
    cluster
        .wait_transaction_state(
            &cluster.a_spec.direct_url(),
            payment_id,
            "coordinator_committed",
        )
        .await?;
    cluster
        .wait_transaction_state(
            &cluster.b_spec.direct_url(),
            payment_id,
            "participant_committed",
        )
        .await?;
    cluster.assert_left_balances(balance).await
}

async fn coordinator_begin_and_abort_tombstone_recover() -> Result<(), String> {
    let key = "begin-tombstone-payment";
    let mut cluster = Cluster::start(
        "begin-tombstone",
        0xe0,
        Some("coordinator_after_begin_fsync"),
        Some("participant_after_abort_tombstone_fsync"),
    )
    .await?;
    if cluster.create_payment(key).await.is_ok() {
        return Err("create unexpectedly survived coordinator begin crash".into());
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    let restored = cluster.only_payment().await?;
    let id = payment_id(&restored)?;
    cluster.expect_b_crash().await?;
    cluster.start_b(None).await?;
    wait_aborted(&cluster, &id).await?;

    if cluster.create_payment(key).await.is_ok() {
        return Err(
            "terminal idempotent retry unexpectedly created or prepared a replacement".into(),
        );
    }
    let replayed = cluster.only_payment().await?;
    if payment_id(&replayed)? != id {
        return Err("ambiguous create retry changed the durable payment id".into());
    }
    Ok(())
}

async fn coordinator_prepare_ack_recover() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "coordinator-prepare-ack",
        0xe2,
        Some("coordinator_after_prepare_ack_fsync"),
        None,
    )
    .await?;
    if cluster
        .create_payment("coordinator-prepare-ack-payment")
        .await
        .is_ok()
    {
        return Err("create unexpectedly survived prepare acknowledgement crash".into());
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    let restored = cluster.only_payment().await?;
    wait_aborted(&cluster, &payment_id(&restored)?).await
}

async fn coordinator_prepared_recover_and_commit() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "coordinator-prepared",
        0xe4,
        Some("coordinator_after_prepare_fsync"),
        None,
    )
    .await?;
    if cluster
        .create_payment("coordinator-prepared-payment")
        .await
        .is_ok()
    {
        return Err("create unexpectedly survived coordinator prepared crash".into());
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    let payment = cluster.only_payment().await?;
    let id = payment_id(&payment)?;
    if cluster
        .transaction_state(&cluster.a_spec.direct_url(), &id)
        .await?
        != "coordinator_prepared"
    {
        return Err("coordinator did not recover the prepared state".into());
    }
    cluster.sign_first_two(&payment).await?;
    cluster.sign(&payment, &cluster.payer).await?;
    wait_committed(&cluster, &id, "3:248").await
}

async fn coordinator_commit_boundary_recover(
    label: &str,
    seed: u8,
    point: &'static str,
) -> Result<(), String> {
    let mut cluster = Cluster::start(label, seed, Some(point), None).await?;
    let payment = cluster.create_payment(&format!("{label}-payment")).await?;
    let id = payment_id(&payment)?;
    cluster.sign_first_two(&payment).await?;
    if cluster.sign(&payment, &cluster.payer).await.is_ok() {
        return Err(format!("final signature unexpectedly survived {point}"));
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    wait_committed(&cluster, &id, "3:248").await?;

    cluster.stop_a();
    cluster.stop_b();
    cluster.start_b(None).await?;
    cluster.start_a(None).await?;
    wait_committed(&cluster, &id, "3:248").await
}

async fn coordinator_abort_boundary_recover(
    label: &str,
    seed: u8,
    point: &'static str,
) -> Result<(), String> {
    let mut cluster = Cluster::start(label, seed, Some(point), None).await?;
    let payment = cluster.create_payment(&format!("{label}-payment")).await?;
    let id = payment_id(&payment)?;
    if cluster
        .fail_payment(&id, "fault matrix abort")
        .await
        .is_ok()
    {
        return Err(format!("abort request unexpectedly survived {point}"));
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    wait_aborted(&cluster, &id).await?;

    cluster.stop_b();
    cluster.start_b(None).await?;
    wait_aborted(&cluster, &id).await
}

async fn coordinator_abort_progress_recover() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "coordinator-abort-progress",
        0xec,
        Some("coordinator_after_abort_progress_fsync"),
        None,
    )
    .await?;
    let payment = cluster
        .create_payment("coordinator-abort-progress-payment")
        .await?;
    let id = payment_id(&payment)?;
    cluster.proxy.set_partitioned(true);
    if cluster
        .fail_payment(&id, "partitioned abort progress")
        .await
        .is_ok()
    {
        return Err("abort request unexpectedly survived abort-progress crash".into());
    }
    cluster.expect_a_crash().await?;
    cluster.proxy.set_partitioned(false);
    cluster.start_a(None).await?;
    wait_aborted(&cluster, &id).await
}

async fn participant_commit_boundary_recover(
    label: &str,
    seed: u8,
    point: &'static str,
) -> Result<(), String> {
    let mut cluster = Cluster::start(label, seed, None, Some(point)).await?;
    let payment = cluster.create_payment(&format!("{label}-payment")).await?;
    let id = payment_id(&payment)?;
    cluster.sign_first_two(&payment).await?;
    let response = cluster.sign(&payment, &cluster.payer).await?;
    if response["payment"]["status"] != "committing" {
        return Err(format!(
            "origin did not retain commit while participant crashed at {point}"
        ));
    }
    cluster.expect_b_crash().await?;
    cluster.start_b(None).await?;
    wait_committed(&cluster, &id, "3:248").await?;
    cluster.stop_b();
    cluster.start_b(None).await?;
    wait_committed(&cluster, &id, "3:248").await
}

async fn participant_abort_boundary_recover() -> Result<(), String> {
    let mut cluster = Cluster::start(
        "participant-abort",
        0xf2,
        None,
        Some("participant_after_abort_fsync"),
    )
    .await?;
    let payment = cluster.create_payment("participant-abort-payment").await?;
    let id = payment_id(&payment)?;
    cluster.fail_payment(&id, "participant abort crash").await?;
    cluster.expect_b_crash().await?;
    cluster.start_b(None).await?;
    wait_aborted(&cluster, &id).await
}

async fn repaired_torn_tail_survives_second_restart() -> Result<(), String> {
    let mut cluster = Cluster::start("torn-tail-repair", 0xf4, None, None).await?;
    let payment = cluster.create_payment("torn-tail-repair-payment").await?;
    let id = payment_id(&payment)?;
    cluster.stop_a();

    let journal_path = PathBuf::from(format!("{}.txlog", cluster.a_spec.state_path.display()));
    let mut journal = OpenOptions::new()
        .append(true)
        .open(&journal_path)
        .map_err(|error| error.to_string())?;
    journal
        .write_all(b"{\"interrupted\":")
        .map_err(|error| error.to_string())?;
    journal.sync_all().map_err(|error| error.to_string())?;
    drop(journal);

    if cluster
        .start_a(Some("journal_after_tail_repair_fsync"))
        .await
        .is_ok()
    {
        return Err("journal repair hook did not crash the process".into());
    }
    cluster.expect_a_crash().await?;
    cluster.start_a(None).await?;
    if cluster
        .transaction_state(&cluster.a_spec.direct_url(), &id)
        .await?
        != "coordinator_prepared"
    {
        return Err("valid journal prefix was not retained after torn-tail repair".into());
    }
    cluster.fail_payment(&id, "torn-tail cleanup").await?;
    wait_aborted(&cluster, &id).await
}

async fn concurrent_idempotent_commits_survive_partition_and_restart() -> Result<(), String> {
    let mut cluster = Cluster::start("concurrent-commit", 0xf6, None, None).await?;
    let (first, replay) = tokio::join!(
        cluster.create_payment("concurrent-same-key"),
        cluster.create_payment("concurrent-same-key")
    );
    let first = first?;
    let replay = replay?;
    if payment_id(&first)? != payment_id(&replay)? {
        return Err("concurrent idempotent creates returned different payment ids".into());
    }
    let second = cluster.create_payment("concurrent-independent-key").await?;
    let first_id = payment_id(&first)?;
    let second_id = payment_id(&second)?;
    cluster.sign_first_two(&first).await?;
    cluster.sign_first_two(&second).await?;

    cluster.proxy.set_partitioned(true);
    let (first_commit, second_commit) = tokio::join!(
        cluster.sign(&first, &cluster.payer),
        cluster.sign(&second, &cluster.payer)
    );
    for response in [first_commit?, second_commit?] {
        if response["payment"]["status"] != "committing" {
            return Err(format!(
                "concurrent partitioned commit was not durable: {response}"
            ));
        }
    }
    cluster.proxy.set_partitioned(false);
    cluster.wait_payment_status(&first_id, "settled").await?;
    cluster.wait_payment_status(&second_id, "settled").await?;
    cluster.assert_left_balances("2:248").await?;

    cluster.stop_a();
    cluster.stop_b();
    cluster.start_b(None).await?;
    cluster.start_a(None).await?;
    wait_committed(&cluster, &first_id, "2:248").await?;
    wait_committed(&cluster, &second_id, "2:248").await
}

pub(super) async fn run_remaining_fault_matrix() -> Result<(), String> {
    coordinator_begin_and_abort_tombstone_recover().await?;
    coordinator_prepare_ack_recover().await?;
    coordinator_prepared_recover_and_commit().await?;
    coordinator_commit_boundary_recover(
        "coordinator-local-apply",
        0xe6,
        "coordinator_after_local_apply",
    )
    .await?;
    coordinator_commit_boundary_recover(
        "coordinator-commit-ack",
        0xe8,
        "coordinator_after_commit_ack_fsync",
    )
    .await?;
    coordinator_commit_boundary_recover(
        "coordinator-committed",
        0xea,
        "coordinator_after_commit_fsync",
    )
    .await?;
    coordinator_abort_boundary_recover(
        "coordinator-abort-decision",
        0xeb,
        "coordinator_after_abort_decision_fsync",
    )
    .await?;
    coordinator_abort_boundary_recover(
        "coordinator-abort-ack",
        0xed,
        "coordinator_after_abort_ack_fsync",
    )
    .await?;
    coordinator_abort_boundary_recover(
        "coordinator-aborted",
        0xee,
        "coordinator_after_abort_fsync",
    )
    .await?;
    coordinator_abort_progress_recover().await?;
    participant_commit_boundary_recover(
        "participant-local-apply",
        0xef,
        "participant_after_local_apply",
    )
    .await?;
    participant_commit_boundary_recover(
        "participant-committed",
        0xf0,
        "participant_after_commit_fsync",
    )
    .await?;
    participant_abort_boundary_recover().await?;
    repaired_torn_tail_survives_second_restart().await?;
    Ok(())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "launches real hubs for concurrent idempotency and partition recovery"]
async fn concurrent_idempotent_commit_regression() {
    concurrent_idempotent_commits_survive_partition_and_restart()
        .await
        .unwrap();
}
