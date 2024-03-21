use super::*;
use ckb_testtool::ckb_types::{bytes::Bytes, core::TransactionBuilder, packed::*, prelude::*};
use ckb_testtool::context::Context;

use k256::ecdsa::signature::SignerMut;
use k256::ecdsa::{self, Signature};
use k256::sha2::{Digest, Sha256};
use rand::thread_rng;

const MAX_CYCLES: u64 = 1000_000_000;

#[test]
fn test_ecverify() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ecdsa-lock");
    let out_point = context.deploy_cell(contract_bin);

    let mut rng = thread_rng();
    let mut signing_key = ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();

    // prepare scripts
    let lock_script = context
        .build_script(
            &out_point,
            Bytes::from(verifying_key.to_sec1_bytes().to_vec()),
        )
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .build();

    let tx_hash = tx.hash().unpack();

    let signature: Signature = signing_key.sign(&tx_hash.0);
    let witness = WitnessArgsBuilder::default()
        .lock(Some(Bytes::from(signature.to_bytes().to_vec())).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}

#[test]
fn test_ecrecover() {
    // deploy contract
    let mut context = Context::default();
    let contract_bin: Bytes = Loader::default().load_binary("ecdsa-recover-lock");
    let out_point = context.deploy_cell(contract_bin);

    let mut rng = thread_rng();
    let signing_key = ecdsa::SigningKey::random(&mut rng);
    let verifying_key = signing_key.verifying_key();
    let pk_hash = Sha256::digest(verifying_key.to_sec1_bytes())[0..20].to_vec();

    // prepare scripts
    let lock_script = context
        .build_script(&out_point, Bytes::from(pk_hash))
        .expect("script");
    let lock_script_dep = CellDep::new_builder().out_point(out_point).build();

    // prepare cells
    let input_out_point = context.create_cell(
        CellOutput::new_builder()
            .capacity(1000u64.pack())
            .lock(lock_script.clone())
            .build(),
        Bytes::new(),
    );
    let input = CellInput::new_builder()
        .previous_output(input_out_point)
        .build();
    let outputs = vec![
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script.clone())
            .build(),
        CellOutput::new_builder()
            .capacity(500u64.pack())
            .lock(lock_script)
            .build(),
    ];

    let outputs_data = vec![Bytes::new(); 2];

    // build transaction
    let tx = TransactionBuilder::default()
        .input(input)
        .outputs(outputs)
        .outputs_data(outputs_data.pack())
        .cell_dep(lock_script_dep)
        .build();

    let tx_hash = tx.hash().unpack();

    let (signature, recid) = signing_key
        .sign_prehash_recoverable(tx_hash.as_bytes())
        .unwrap();

    let signature_with_recid = [&[recid.to_byte()], signature.to_bytes().as_slice()].concat();

    let witness = WitnessArgsBuilder::default()
        .lock(Some(Bytes::from(signature_with_recid)).pack())
        .build();
    let tx = tx
        .as_advanced_builder()
        .witness(witness.as_bytes().pack())
        .build();
    let tx = context.complete_tx(tx);

    // run
    let cycles = context
        .verify_tx(&tx, MAX_CYCLES)
        .expect("pass verification");
    println!("consume cycles: {}", cycles);
}
