use std::vec;

use num_bigint::BigUint;
use num_traits::FromPrimitive;
use rand::RngCore;
use sha2::{digest::DynDigest, Digest, Sha256};

use crate::{
    convert::{i2osp, os2ip, string_xor},
    errors::{Error, Result},
    plain_rsa::{PrivateKey, PublicKey},
};

fn mgf1(seed: &[u8], mask_len: usize) -> Result<Vec<u8>> {
    let sha256: &mut dyn DynDigest = &mut Sha256::new();
    let h_len = sha256.output_size();
    if mask_len > 2_usize.pow(32) * h_len {
        return Err(Error::MaskTooLong);
    }

    let mut output: Vec<u8> = Vec::new();
    let upper_bound = mask_len / h_len - 1;
    for i in 0..upper_bound {
        let c: Vec<u8> = i2osp(&BigUint::from_usize(i).unwrap(), 4).unwrap();
        let seed_c = &[seed, &c].concat();
        sha256.update(&seed_c);
        let mut hash = vec![0_u8; h_len];
        match sha256.finalize_into_reset(&mut hash) {
            Err(_) => return Err(Error::InvalidBufferSize),
            _ => (),
        };
        output.append(&mut hash.to_vec());
    }

    Ok(output)
}

pub fn oaep_encrypt(pk: &PublicKey, msg: &str) -> Result<Vec<u8>> {
    oaep_encrypt_with_label(pk, msg, "")
}

pub fn oaep_encrypt_with_label(pk: &PublicKey, msg: &str, label: &str) -> Result<Vec<u8>> {
    let sha256: &mut dyn DynDigest = &mut Sha256::new();
    let h_len = sha256.output_size();
    let k = (pk.n.bits() as usize) / 8;
    let max_msg_len = k - 2 * h_len - 2;

    // check length
    if msg.len() > max_msg_len {
        return Err(Error::MessageTooLong);
    }

    // EME-OAEP encoding
    let mut label_hash = vec![0_u8; h_len];
    sha256.update(label.as_bytes());
    match sha256.finalize_into_reset(&mut label_hash) {
        Err(_) => return Err(Error::InvalidBufferSize),
        _ => (),
    };

    let ps = vec![0_u8; max_msg_len - msg.len()];
    let db = [label_hash, ps, vec![0x01], msg.as_bytes().to_vec()].concat();

    let mut seed = vec![0_u8; h_len];
    let mut rng = rand::thread_rng();
    rng.fill_bytes(&mut seed);

    let db_mask = mgf1(&seed, k - h_len - 1).unwrap();
    let masked_db = string_xor(&db, &db_mask).unwrap();

    let seed_mask = mgf1(&masked_db, h_len).unwrap();
    let masked_seed = string_xor(&seed, &seed_mask).unwrap();

    let em = vec![&[0x00_u8][..], &masked_seed[..], &masked_db[..]].concat();

    // RSA encryption
    let m = os2ip(&em).unwrap();
    let c = pk.encrypt_plain(&m.to_string()).unwrap();
    let output = i2osp(&c, k);
    output
}

pub fn oaep_decrypt(sk: &PrivateKey, ciphertext: &[u8]) -> Result<Vec<u8>> {
    oaep_decrypt_with_label(sk, ciphertext, "")
}

pub fn oaep_decrypt_with_label(sk: &PrivateKey, ciphertext: &[u8], label: &str) -> Result<Vec<u8>> {
    let sha256: &mut dyn DynDigest = &mut Sha256::new();
    let h_len = sha256.output_size();
    let k = sk.n.bits() as usize / 8;

    // check length
    if k != ciphertext.len() || k < 2 * h_len + 2 {
        return Err(Error::DecryptionError);
    }

    // RSA decryption
    let c = os2ip(ciphertext).unwrap();
    let m = sk.decrypt_plain(&c.to_string()).unwrap();
    let em = i2osp(&m, k).unwrap();

    // EME-OAEP decoding
    let mut label_hash = vec![0_u8; h_len];
    sha256.update(label.as_bytes());
    match sha256.finalize_into_reset(&mut label_hash) {
        Err(_) => return Err(Error::InvalidBufferSize),
        _ => (),
    };
    let y = em[0];
    let mut masked_seed = vec![0_u8; h_len];
    masked_seed.copy_from_slice(&em[1..h_len + 1]);
    let mut masked_db = vec![0_u8; k - h_len - 1];
    masked_db.copy_from_slice(&em[h_len + 1..]);

    if y != 0 {
        return Err(Error::DecryptionError);
    }

    let seed_mask = mgf1(&masked_db, h_len).unwrap();
    let seed = string_xor(&masked_seed, &seed_mask).unwrap();

    let db_mask = mgf1(&seed, k - h_len - 1).unwrap();
    let db = string_xor(&masked_db, &db_mask).unwrap();

    let mut label_hash_in_db = vec![0_u8; h_len];
    label_hash_in_db.copy_from_slice(&db[..h_len]);

    if label_hash_in_db != label_hash {
        return Err(Error::DecryptionError);
    }

    let mut msg_st = h_len;
    loop {
        match db[msg_st] {
            0x00 => msg_st += 1,
            0x01 => break,
            _ => return Err(Error::DecryptionError),
        };
        if msg_st == db.len() - 1 {
            return Err(Error::DecryptionError);
        }
    }

    msg_st += 1;
    let mut msg = vec![0_u8; db.len() - msg_st];
    msg.copy_from_slice(&db[msg_st..]);

    Ok(msg)
}
