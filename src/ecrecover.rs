//! ecrecover-bench ecrecover implementation.
//! Original implementation: solana/programs/bpf_loader/src/syscalls.rs

use crate::keccak;
use solana_rbpf::error::{EbpfError, UserDefinedError};
use solana_rbpf::memory_region::{AccessType, MemoryMapping};
use solana_sdk::instruction::InstructionError;
use solana_sdk::pubkey::{Pubkey, PubkeyError};
use std::fmt;
use std::mem::{align_of, size_of};
use std::slice::from_raw_parts_mut;
use std::str::{FromStr, Utf8Error};

/// Error definitions
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum SyscallError {
    #[error("{0}: {1:?}")]
    InvalidString(Utf8Error, Vec<u8>),
    #[error("BPF program panicked")]
    Abort,
    #[error("BPF program Panicked in {0} at {1}:{2}")]
    Panic(String, u64, u64),
    #[error("cannot borrow invoke context")]
    InvokeContextBorrowFailed,
    #[error("malformed signer seed: {0}: {1:?}")]
    MalformedSignerSeed(Utf8Error, Vec<u8>),
    #[error("Could not create program address with signer seeds: {0}")]
    BadSeeds(PubkeyError),
    #[error("Program {0} not supported by inner instructions")]
    ProgramNotSupported(Pubkey),
    #[error("{0}")]
    InstructionError(InstructionError),
    #[error("Unaligned pointer")]
    UnalignedPointer,
    #[error("Too many signers")]
    TooManySigners,
    #[error("Instruction passed to inner instruction is too large ({0} > {1})")]
    InstructionTooLarge(usize, usize),
    #[error("Too many accounts passed to inner instruction")]
    TooManyAccounts,
}

/// Errors returned by functions the BPF Loader registers with the VM
#[derive(Debug, thiserror::Error, PartialEq)]
pub enum BpfError {
    VerifierError,
    SyscallError,
}

impl fmt::Display for BpfError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            BpfError::VerifierError => write!(f, "VerifierError"),
            BpfError::SyscallError => write!(f, "SyscallError"),
        }
    }
}

impl UserDefinedError for BpfError {}

impl From<SyscallError> for BpfError {
    fn from(_error: SyscallError) -> Self {
        BpfError::SyscallError
    }
}

impl From<SyscallError> for EbpfError<BpfError> {
    fn from(error: SyscallError) -> Self {
        EbpfError::UserError(error.into())
    }
}

/// Error handling for SyscallObject::call methods
macro_rules! question_mark {
    ( $value:expr, $result:ident ) => {{
        let value = $value;
        match value {
            Err(err) => {
                *$result = Err(err.into());
                return;
            }
            Ok(value) => value,
        }
    }};
}

fn translate(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
) -> Result<u64, EbpfError<BpfError>> {
    memory_mapping.map::<BpfError>(access_type, vm_addr, len)
}

fn translate_slice_inner<'a, T>(
    memory_mapping: &MemoryMapping,
    access_type: AccessType,
    vm_addr: u64,
    len: u64,
    _loader_id: &Pubkey,
    enforce_aligned_host_addrs: bool,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    if !enforce_aligned_host_addrs && (vm_addr as u64 as *mut T).align_offset(align_of::<T>()) != 0
    {
        return Err(SyscallError::UnalignedPointer.into());
    }
    if len == 0 {
        return Ok(&mut []);
    }

    let host_addr = translate(
        memory_mapping,
        access_type,
        vm_addr,
        len.saturating_mul(size_of::<T>() as u64),
    )?;

    if enforce_aligned_host_addrs && (host_addr as *mut T).align_offset(align_of::<T>()) != 0 {
        return Err(SyscallError::UnalignedPointer.into());
    }
    Ok(unsafe { from_raw_parts_mut(host_addr as *mut T, len as usize) })
}

fn translate_slice_mut<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    loader_id: &Pubkey,
    enforce_aligned_host_addrs: bool,
) -> Result<&'a mut [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Store,
        vm_addr,
        len,
        loader_id,
        enforce_aligned_host_addrs,
    )
}

fn translate_slice<'a, T>(
    memory_mapping: &MemoryMapping,
    vm_addr: u64,
    len: u64,
    loader_id: &Pubkey,
    enforce_aligned_host_addrs: bool,
) -> Result<&'a [T], EbpfError<BpfError>> {
    translate_slice_inner::<T>(
        memory_mapping,
        AccessType::Load,
        vm_addr,
        len,
        loader_id,
        enforce_aligned_host_addrs,
    )
    .map(|value| &*value)
}

// Ecrecover
pub struct SyscallEcrecover {
    loader_id: Pubkey,
}

impl SyscallEcrecover {
    pub fn new() -> Self {
        SyscallEcrecover {
            loader_id: Pubkey::from_str("Cj9ydNGWLePKRztuE3m3zT1uvj2We517k55vq2e65jtP")
                .expect("Invalid solana_sdk::pubkey::Pubkey from string"),
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn call(
        &self,
        hash_addr: u64,
        recovery_id_val: u64,
        signature_addr: u64,
        result_addr: u64,
        _arg5: u64,
        memory_mapping: &MemoryMapping,
        result: &mut Result<u64, EbpfError<BpfError>>,
    ) {
        let hash = question_mark!(
            translate_slice::<u8>(
                memory_mapping,
                hash_addr,
                keccak::HASH_BYTES as u64,
                &self.loader_id,
                true,
            ),
            result
        );
        let signature = question_mark!(
            translate_slice::<u8>(memory_mapping, signature_addr, 64u64, &self.loader_id, true,),
            result
        );
        let ecrecover_result = question_mark!(
            translate_slice_mut::<u8>(memory_mapping, result_addr, 64u64, &self.loader_id, true,),
            result
        );

        let message = match libsecp256k1::Message::parse_slice(hash) {
            Ok(msg) => msg,
            Err(_) => {
                *result = Ok(1);
                return;
            }
        };
        let recovery_id = match libsecp256k1::RecoveryId::parse(recovery_id_val as u8) {
            Ok(id) => id,
            Err(_) => {
                *result = Ok(2);
                return;
            }
        };
        let signature = match libsecp256k1::Signature::parse_standard_slice(signature) {
            Ok(sig) => sig,
            Err(_) => {
                *result = Ok(3);
                return;
            }
        };

        let public_key = match libsecp256k1::recover(&message, &signature, &recovery_id) {
            Ok(key) => key.serialize(),
            Err(_) => {
                *result = Ok(4);
                return;
            }
        };

        ecrecover_result.copy_from_slice(&public_key[1..65]);
        *result = Ok(0);
    }
}
