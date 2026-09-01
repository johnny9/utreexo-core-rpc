use bitcoin::BlockHash;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::hashes::Hash;
use floresta_chain::ScriptPubKeyKind;
use floresta_wire::block_proof::{Bitmap, GetUtreexoProof, UtreexoProof, UtreexoProofMask};

fn decode_hex(value: &str) -> Vec<u8> {
    assert_eq!(value.len() % 2, 0);
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let text = std::str::from_utf8(pair).unwrap();
            u8::from_str_radix(text, 16).unwrap()
        })
        .collect()
}

#[test]
fn current_floresta_decodes_sidecar_uproof_vector() {
    let payload = decode_hex(&format!(
        "{}01{}0201fd2c010203000000050000000000000000015104000000060000000000000002",
        "11".repeat(32),
        "22".repeat(32),
    ));
    let proof: UtreexoProof = deserialize(&payload).unwrap();
    assert_eq!(proof.block_hash.to_byte_array(), [0x11; 32]);
    assert_eq!(proof.proof_hashes.len(), 1);
    assert_eq!(&*proof.proof_hashes[0], &[0x22; 32]);
    assert_eq!(proof.targets, [1, 300]);
    assert_eq!(proof.leaf_data.len(), 2);
    assert_eq!(proof.leaf_data[0].header_code, 3);
    assert_eq!(proof.leaf_data[0].amount, 5);
    assert_eq!(
        proof.leaf_data[0].spk_ty,
        ScriptPubKeyKind::Other(vec![0x51].into_boxed_slice())
    );
    assert_eq!(proof.leaf_data[1].header_code, 4);
    assert_eq!(proof.leaf_data[1].amount, 6);
    assert_eq!(
        proof.leaf_data[1].spk_ty,
        ScriptPubKeyKind::WitnessV0PubKeyHash
    );
}

#[test]
fn sidecar_parser_vector_matches_current_floresta_getuproof() {
    let request = GetUtreexoProof {
        block_hash: BlockHash::from_byte_array([0x11; 32]),
        request_bitmap: UtreexoProofMask::request_all(),
        proof_hashes_bitmap: Bitmap::new(),
        leaf_index_bitmap: Bitmap::new(),
    };
    assert_eq!(
        serialize(&request),
        decode_hex(&format!("{}070000", "11".repeat(32)))
    );
}
