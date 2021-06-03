//! ecrecover-bench main module.

#![deny(warnings)]
#![deny(missing_docs)]

mod cli;
mod ecrecover;
mod keccak;
mod sanitize;

fn main() {
    init_logger();
    execute(cli::application());
}

/// Initializes the logger.
fn init_logger() {
    if std::env::var("RUST_LOG").is_err() {
        std::env::set_var("RUST_LOG", "info");
    }
    tracing_subscriber::fmt::init();
}

/// Dispatches CLI commands.
fn execute(app: cli::Application) {
    keccak_bench(app.count, app.size);
    ecrecover_bench(app.count, app.size);
}

use std::time::Instant;
use tracing::{error, info};

/// Runs the keccak benchmark.
fn keccak_bench(count: usize, message_size: usize) {
    info!("Preparing {} buffers of {} bytes...", count, message_size);
    let mut buf: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        buf.push((0..message_size).map(|_| rand::random::<u8>()).collect());
    }

    info!(">Start keccak256...");

    let now = Instant::now();
    for i in 0..count {
        keccak_run(&buf[i]);
    }
    let d = now.elapsed();

    info!("Finish keccak256");
    info!("Keccak ({}) elapsed {} sec.", count, d.as_secs());
}

/// Executes one keccak256 call.
#[inline]
fn keccak_run(buf: &[u8]) {
    let _ = keccak::hash(buf);
}

use crate::ecrecover::SyscallEcrecover;

/// Runs the ecrecover benchmark.
fn ecrecover_bench(count: usize, message_size: usize) {
    use k256::ecdsa::{signature::Signer, Signature, SigningKey};
    use rand_core::OsRng;

    info!("Preparing {} signatures of 64 bytes...", count);
    let signing_key = SigningKey::random(&mut OsRng);
    let mut buf: Vec<Signature> = Vec::with_capacity(count);
    for _ in 0..count {
        let msg: Vec<_> = (0..message_size).map(|_| rand::random::<u8>()).collect();
        let signature: Signature = signing_key.sign(&msg);
        buf.push(signature);
    }

    let caller = SyscallEcrecover::new();

    info!(">Start ecrecover...");

    let now = Instant::now();
    for i in 0..count {
        ecrecover_run(&caller, buf[i].as_ref());
    }
    let d = now.elapsed();

    info!("Finish ecrecover");
    info!("Ecrecover ({}) elapsed {} sec.", count, d.as_secs());
}

/// Executes one ecrecover call.
#[inline]
fn ecrecover_run(ecrecv: &SyscallEcrecover, buf: &[u8]) {
    use crate::ecrecover::BpfError;
    use solana_rbpf::error::EbpfError;
    use solana_rbpf::memory_region::{MemoryMapping, MemoryRegion};
    use solana_rbpf::vm::Config;

    let hash_addr = 0_u64;
    let recovery_id_val = 0_u64;
    let signature_addr = 0_u64;
    let result_addr = 0_u64;
    let val_va = 0x1000;

    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<BpfError>(
        vec![MemoryRegion::new_from_slice(buf, val_va, 0, true)],
        &config,
    )
    .unwrap();
    let mut result: Result<u64, EbpfError<BpfError>> = Ok(0);

    ecrecv.call(
        hash_addr,
        recovery_id_val,
        signature_addr,
        result_addr,
        0,
        &memory_mapping,
        &mut result,
    );

    if let Err(err) = result {
        error!("{}", err);
        panic!("{:?}", err);
    }
}
