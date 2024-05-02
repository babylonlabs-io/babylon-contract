use bitcoin::blockdata::opcodes::all::*;
use bitcoin::blockdata::script::Builder;
use bitcoin::key::Secp256k1;
use bitcoin::secp256k1::PublicKey;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, XOnlyPublicKey};
use bitcoin::{Network, ScriptBuf};

const UNSPENDABLE_KEY: &str = "0250929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0";

fn unspendable_key_path_internal_pub_key() -> XOnlyPublicKey {
    let key_bytes = hex::decode(UNSPENDABLE_KEY).unwrap();

    let (pk_x, _) = PublicKey::from_slice(&key_bytes)
        .unwrap()
        .x_only_public_key();
    pk_x
}

// sort_keys sorts public keys in lexicographical order
pub fn sort_keys(keys: &mut [XOnlyPublicKey]) {
    keys.sort_by(|a, b| {
        let a_serialized = a.serialize();
        let b_serialized = b.serialize();
        a_serialized.cmp(&b_serialized)
    });
}

/// prepare_keys_for_multisig_script prepares keys for multisig, ensuring there are no duplicates
pub fn prepare_keys_for_multisig_script(
    keys: &[XOnlyPublicKey],
) -> Result<Vec<XOnlyPublicKey>, String> {
    if keys.len() < 2 {
        return Err("Cannot create multisig script with less than 2 keys".to_string());
    }

    let mut sorted_keys = keys.to_vec();
    sort_keys(&mut sorted_keys);

    // Check for duplicates
    for window in sorted_keys.windows(2) {
        if window[0] == window[1] {
            return Err("Duplicate key in list of keys".to_string());
        }
    }

    Ok(sorted_keys)
}

/// assemble_multisig_script assembles a multisig script
fn assemble_multisig_script(
    pubkeys: &[XOnlyPublicKey],
    quorum: usize,
    with_verify: bool,
) -> Result<ScriptBuf, String> {
    if quorum > pubkeys.len() {
        return Err("Quorum cannot be greater than the number of keys".to_string());
    }

    let mut builder = Builder::new();
    for (i, key) in pubkeys.iter().enumerate() {
        builder = builder.push_slice(key.serialize());
        if i == 0 {
            builder = builder.push_opcode(OP_CHECKSIG);
        } else {
            builder = builder.push_opcode(OP_CHECKSIGADD);
        }
    }

    builder = builder.push_int(quorum as i64);
    if with_verify {
        builder = builder.push_opcode(OP_NUMEQUALVERIFY);
    } else {
        builder = builder.push_opcode(OP_NUMEQUAL);
    }

    Ok(builder.into_script())
}

/// build_multisig_script creates a multisig script
pub fn build_multisig_script(
    keys: &[XOnlyPublicKey],
    quorum: usize,
    with_verify: bool,
) -> Result<ScriptBuf, String> {
    let prepared_keys = prepare_keys_for_multisig_script(keys)?;
    assemble_multisig_script(&prepared_keys, quorum, with_verify)
}

/// build_time_lock_script creates a timelock script
pub fn build_time_lock_script(
    pub_key: &XOnlyPublicKey,
    lock_time: u16,
) -> Result<ScriptBuf, String> {
    let builder = Builder::new()
        .push_slice(pub_key.serialize())
        .push_opcode(OP_CHECKSIGVERIFY)
        .push_int(lock_time as i64)
        .push_opcode(OP_CSV);
    let script = builder.into_script();
    Ok(script)
}

/// build_single_key_sig_script builds a single key signature script
pub fn build_single_key_sig_script(
    pub_key: &XOnlyPublicKey,
    with_verify: bool,
) -> Result<ScriptBuf, String> {
    let mut builder = Builder::new().push_slice(pub_key.serialize());

    if with_verify {
        builder = builder.push_opcode(OP_CHECKSIGVERIFY);
    } else {
        builder = builder.push_opcode(OP_CHECKSIG);
    }

    Ok(builder.into_script())
}

pub fn build_relative_time_lock_pk_script(
    pk: &XOnlyPublicKey,
    lock_time: u16,
    network: Network,
) -> Result<ScriptBuf, String> {
    let secp = Secp256k1::new();

    // Assuming the unspendableKeyPathInternalPubKey function exists and is imported
    let unspendable_key_path_key = unspendable_key_path_internal_pub_key();

    let script = build_time_lock_script(pk, lock_time)?;

    let mut builder = TaprootBuilder::new();
    builder = builder
        .add_leaf(0, script.clone())
        .map_err(|_| "failed to add leaf")?;
    let taproot_spend_info = builder
        .finalize(&secp, unspendable_key_path_key)
        .map_err(|_| "failed to finalize taproot")?;

    let secp = Secp256k1::verification_only();
    let taproot_address = Address::p2tr(
        &secp,
        taproot_spend_info.internal_key(),
        taproot_spend_info.merkle_root(),
        network,
    );
    let taproot_pk_script = taproot_address.script_pubkey();

    Ok(taproot_pk_script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};

    // Function to generate a public key from a secret key
    fn generate_public_key(data: &[u8]) -> XOnlyPublicKey {
        let secp = Secp256k1::new();
        let secret_key = SecretKey::from_slice(data).expect("slice with correct length");
        let (pk_x, _) = PublicKey::from_secret_key(&secp, &secret_key).x_only_public_key();
        pk_x
    }

    #[test]
    fn test_sort_keys() {
        // Generate public keys with known secret keys
        let mut keys = vec![
            generate_public_key(&[1; 32]), // Minimal valid secret key
            generate_public_key(&[2; 32]), // Another minimal valid secret key
            generate_public_key(&[3; 32]), // Another minimal valid secret key
        ];

        // Sort the keys using the function under test
        sort_keys(&mut keys);

        // Serialize the keys to compare them easily
        let serialized_keys: Vec<Vec<u8>> =
            keys.iter().map(|key| key.serialize().to_vec()).collect();

        // Ensure they are sorted lexicographically
        assert!(
            serialized_keys.windows(2).all(|w| w[0] <= w[1]),
            "Keys should be sorted lexicographically"
        );
    }
}
