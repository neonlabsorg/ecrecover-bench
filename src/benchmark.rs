//! ecrecover-bench benchmark module.

/// Runs the benchmark.
pub fn run(count: usize, size: usize) {
    let buffers = generate_buffers(count, size);
    let k = keccak_bench(&buffers);

    let signatures = generate_signatures(&buffers);
    ecrecover_bench_libsecp256k1(signatures, k);

    let signatures = generate_signatures(&buffers);
    ecrecover_bench_k256(signatures, k);

    let signatures = generate_signatures(&buffers);
    ecrecover_bench_secp256k1(signatures, k);
}

use crate::{keccak, significant};
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

const PRECISION: usize = 4;

/// Runs the keccak benchmark and returns total and average elapsed time.
fn keccak_bench(buffers: &[Vec<u8>]) -> (f64, f64) {
    info!(">Start keccak256...");

    let now = Instant::now();
    for b in buffers {
        keccak_run(b);
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let total = nanos / 1E9;
    let n = buffers.len() as f64;
    let average = total / n;

    info!("Finish keccak256");
    info!(
        "Keccak ({} executions) elapsed {} s.",
        n,
        significant::precision(total, PRECISION)
    );
    info!(
        "Keccak average: {} s.",
        significant::precision(average, PRECISION)
    );

    (total, average)
}

/// Executes single keccak256 call.
#[inline]
fn keccak_run(msg: &[u8]) {
    let _ = keccak::hash(msg);
}

use crate::ecrecover::{BpfError, SyscallEcrecoverLibsecp256k1, SyscallEcrecoverK256, SyscallEcrecoverSecp256k1};
use k256::ecdsa::Signature;

/// Generates ECDSA signatures for the benchmark.
fn generate_signatures(buffers: &[Vec<u8>]) -> Vec<Signature> {
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

use solana_rbpf::vm::Config;

/// Runs the ecrecover benchmark.
fn ecrecover_bench_libsecp256k1(signatures: Vec<Signature>, k: (f64, f64)) {
    info!(">Start ecrecover libsecp256k1...");

    let caller = SyscallEcrecoverLibsecp256k1::new();
    let config = Config::default();

    let now = Instant::now();
    for s in &signatures {
        ecrecover_run_libsecp256k1(&caller, &config, s.as_ref());
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let total = nanos / 1E9;
    let n = signatures.len() as f64;
    let average = total / n;

    info!("Finish ecrecover libsecp256k1");
    info!(
        "Ecrecover libsecp256k1 ({} executions) elapsed {} s. = {} K",
        n,
        significant::precision(total, PRECISION),
        significant::precision(total / k.0, PRECISION)
    );
    info!(
        "Ecrecover libsecp256k1 average: {} s. = {} K",
        significant::precision(average, PRECISION),
        significant::precision(average / k.1, PRECISION)
    );
}

/// Runs the ecrecover benchmark.
fn ecrecover_bench_k256(signatures: Vec<Signature>, k: (f64, f64)) {
    info!(">Start ecrecover k256...");

    let caller = SyscallEcrecoverK256::new();
    let config = Config::default();

    let now = Instant::now();
    for s in &signatures {
        ecrecover_run_k256(&caller, &config, s.as_ref());
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let total = nanos / 1E9;
    let n = signatures.len() as f64;
    let average = total / n;

    info!("Finish ecrecover k256");
    info!(
        "Ecrecover k256 ({} executions) elapsed {} s. = {} K",
        n,
        significant::precision(total, PRECISION),
        significant::precision(total / k.0, PRECISION)
    );
    info!(
        "Ecrecover k256 average: {} s. = {} K",
        significant::precision(average, PRECISION),
        significant::precision(average / k.1, PRECISION)
    );
}

/// Runs the ecrecover benchmark.
fn ecrecover_bench_secp256k1(signatures: Vec<Signature>, k: (f64, f64)) {
    info!(">Start ecrecover secp256k1...");

    let caller = SyscallEcrecoverSecp256k1::new();
    let config = Config::default();

    let now = Instant::now();
    for s in &signatures {
        ecrecover_run_secp256k1(&caller, &config, s.as_ref());
    }
    let d = now.elapsed();

    let nanos = d.as_nanos() as f64;
    let total = nanos / 1E9;
    let n = signatures.len() as f64;
    let average = total / n;

    info!("Finish ecrecover secp256k1");
    info!(
        "Ecrecover secp256k1 ({} executions) elapsed {} s. = {} K",
        n,
        significant::precision(total, PRECISION),
        significant::precision(total / k.0, PRECISION)
    );
    info!(
        "Ecrecover secp256k1 average: {} s. = {} K",
        significant::precision(average, PRECISION),
        significant::precision(average / k.1, PRECISION)
    );
}

/// Executes single ecrecover call.
#[inline]
fn ecrecover_run_libsecp256k1(ecrecv: &SyscallEcrecoverLibsecp256k1, config: &Config, signature: &[u8]) {
    use solana_rbpf::memory_region::{MemoryMapping, MemoryRegion};
    let memory_mapping = MemoryMapping::new::<BpfError>(
        vec![MemoryRegion::new_from_slice(signature, 0, 0, true)],
        config,
    )
    .unwrap();

    use solana_rbpf::error::EbpfError;
    let mut result: Result<u64, EbpfError<BpfError>> = Ok(0);
    ecrecv.call(0, 0, 0, 0, 0, &memory_mapping, &mut result);

    if let Err(err) = result {
        error!("{}", err);
        panic!("{:?}", err);
    }
    assert_eq!(result.unwrap(), 0);
}

/// Executes single ecrecover call.
#[inline]
fn ecrecover_run_k256(ecrecv: &SyscallEcrecoverK256, config: &Config, signature: &[u8]) {
    use solana_rbpf::memory_region::{MemoryMapping, MemoryRegion};
    let memory_mapping = MemoryMapping::new::<BpfError>(
        vec![MemoryRegion::new_from_slice(signature, 0, 0, true)],
        config,
    )
    .unwrap();

    use solana_rbpf::error::EbpfError;
    let mut result: Result<u64, EbpfError<BpfError>> = Ok(0);
    ecrecv.call(0, 0, 0, 0, 0, &memory_mapping, &mut result);

    if let Err(err) = result {
        error!("{}", err);
        panic!("{:?}", err);
    }
    assert_eq!(result.unwrap(), 0);
}

/// Executes single ecrecover call.
#[inline]
fn ecrecover_run_secp256k1(ecrecv: &SyscallEcrecoverSecp256k1, config: &Config, signature: &[u8]) {
    use solana_rbpf::memory_region::{MemoryMapping, MemoryRegion};
    let memory_mapping = MemoryMapping::new::<BpfError>(
        vec![MemoryRegion::new_from_slice(signature, 0, 0, true)],
        config,
    )
    .unwrap();

    use solana_rbpf::error::EbpfError;
    let mut result: Result<u64, EbpfError<BpfError>> = Ok(0);
    ecrecv.call(0, 0, 0, 0, 0, &memory_mapping, &mut result);

    if let Err(err) = result {
        error!("{}", err);
        panic!("{:?}", err);
    }
    assert_eq!(result.unwrap(), 0);
}