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
    let buffers = generate_buffers(app.count, app.size);
    let r = keccak_bench(&buffers);

    let signatures = generate_signatures(&buffers);
    ecrecover_bench(&signatures, r);
}

use std::time::Instant;
use tracing::{error, info};

/// Generates random data.
fn generate_buffers(count: usize, message_size: usize) -> Vec<Vec<u8>> {
    info!(
        "Preparing {} buffers of {} bytes each...",
        count, message_size
    );

    let mut buffers: Vec<Vec<u8>> = Vec::with_capacity(count);
    for _ in 0..count {
        buffers.push((0..message_size).map(|_| rand::random::<u8>()).collect());
    }
    buffers
}

/// Runs the keccak benchmark.
fn keccak_bench(buffers: &Vec<Vec<u8>>) -> (f64, f64) {
    info!(">Start keccak256...");

    let now = Instant::now();
    for b in buffers {
        keccak_run(b);
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let sec = nanos / 1E9;
    let n = buffers.len() as f64;
    let average = sec / n;

    info!("Finish keccak256");
    info!("Keccak ({} executions) elapsed {} s.", n, sec);
    info!("Keccak average: {} s.", average);

    (sec, average)
}

/// Executes single keccak256 call.
#[inline]
fn keccak_run(msg: &[u8]) {
    let _ = keccak::hash(msg);
}

use crate::ecrecover::SyscallEcrecover;
use k256::ecdsa::Signature;

/// Generates ECDSA signatures for the benchmark.
fn generate_signatures(buffers: &Vec<Vec<u8>>) -> Vec<Signature> {
    use k256::ecdsa::{signature::Signer, SigningKey};
    use rand_core::OsRng;

    info!("Preparing {} signatures of 64 bytes...", buffers.len());
    let signing_key = SigningKey::random(&mut OsRng);
    let mut signatures: Vec<Signature> = Vec::with_capacity(buffers.len());
    for b in buffers {
        signatures.push(signing_key.sign(b));
    }
    signatures
}

/// Runs the ecrecover benchmark.
fn ecrecover_bench(signatures: &Vec<Signature>, k: (f64, f64)) {
    let caller = SyscallEcrecover::new();

    info!(">Start ecrecover...");

    let now = Instant::now();
    for s in signatures {
        ecrecover_run(&caller, s.as_ref());
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let sec = nanos / 1E9;
    let n = signatures.len() as f64;
    let average = sec / n;

    info!("Finish ecrecover");
    info!(
        "Ecrecover ({} executions) elapsed {} s. = {} K",
        n,
        sec,
        sec / k.0
    );
    info!("Ecrecover average: {} s. = {} K", average, average / k.1);
}

/// Executes single ecrecover call.
#[inline]
fn ecrecover_run(ecrecv: &SyscallEcrecover, signature: &[u8]) {
    use crate::ecrecover::BpfError;
    use solana_rbpf::error::EbpfError;
    use solana_rbpf::memory_region::{MemoryMapping, MemoryRegion};
    use solana_rbpf::vm::Config;

    let config = Config::default();
    let memory_mapping = MemoryMapping::new::<BpfError>(
        vec![MemoryRegion::new_from_slice(signature, 0, 0, true)],
        &config,
    )
    .unwrap();

    let mut result: Result<u64, EbpfError<BpfError>> = Ok(0);
    ecrecv.call(0, 0, 0, 0, 0, &memory_mapping, &mut result);

    if let Err(err) = result {
        error!("{}", err);
        panic!("{:?}", err);
    }
    assert_eq!(result.unwrap(), 0);
}
