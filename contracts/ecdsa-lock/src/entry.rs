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
use k256::ecdsa::{signature::Verifier, Signature, VerifyingKey};

use crate::error::Error;

pub fn main() -> Result<(), Error> {
    // remove below examples and write your code here
    let script = load_script()?;
    let args: Vec<u8> = script.args().unpack();
    debug!("script args is {:?}", args);

    let tx_hash = load_tx_hash()?;
    debug!("tx hash is {:?}", tx_hash);

    let witness = load_witness_args(0, Source::Input).unwrap();

    let signature = match witness.lock().to_opt() {
        Some(witness) => match Signature::from_slice(&witness.raw_data()) {
            Ok(signature) => signature,
            Err(_) => return Err(Error::VerificationError),
        },
        None => return Err(Error::VerificationError),
    };

    let verify_key = VerifyingKey::from_sec1_bytes(&args).map_err(|_| Error::VerificationError)?;
    match verify_key.verify(&tx_hash, &signature) {
        Ok(_) => Ok(()),
        Err(_) => return Err(Error::VerificationError),
    }
}
