// Import from `core` instead of from `std` since we are in no-std mode
use core::result::Result;

// Import heap related library from `alloc`
// https://doc.rust-lang.org/alloc/index.html
use alloc::vec::Vec;

// Import CKB syscalls and structures
// https://nervosnetwork.github.io/ckb-std/riscv64imac-unknown-none-elf/doc/ckb_std/index.html
use ckb_std::{
    ckb_constants::Source,
    ckb_types::prelude::Unpack,
    debug,
    high_level::{load_script, load_tx_hash, load_witness_args},
};
use k256::{
    ecdsa::{RecoveryId, Signature, VerifyingKey},
    sha2::{Digest, Sha256},
};

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let pk_hash: Vec<u8> = script.args().unpack();
    debug!("pk_hash is {:?}", pk_hash);

    let tx_hash = load_tx_hash()?;
    debug!("tx hash is {:?}", tx_hash);

    let witness = load_witness_args(0, Source::Input).unwrap();

    let (recid, signature) = match witness.lock().to_opt() {
        Some(signature_with_recid) => {
            let signature_with_recid = signature_with_recid.raw_data();
            debug!("signature_with_recid len: {}", signature_with_recid.len());
            match (
                RecoveryId::from_byte(signature_with_recid[0]),
                Signature::from_slice(&signature_with_recid[1..]),
            ) {
                (Some(recid), Ok(signature)) => (recid, signature),
                _ => return Err(Error::VerificationError),
            }
        }
        None => return Err(Error::VerificationError),
    };

    let recovered_key = match VerifyingKey::recover_from_prehash(&tx_hash, &signature, recid) {
        Ok(recovered_key) => recovered_key,
        Err(_) => return Err(Error::VerificationError),
    };

    let recovered_pk_hash = Sha256::digest(recovered_key.to_sec1_bytes())[0..20].to_vec();
    if pk_hash != recovered_pk_hash {
        return Err(Error::VerificationError);
    }

    Ok(())
}
