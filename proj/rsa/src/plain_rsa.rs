// Plain RSA
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::str;

use base64::{engine::general_purpose, Engine};
use num::Num;
use num_bigint::BigUint;

use crate::errors::{Error, Result};
use crate::generator::Generator;

#[derive(Clone, PartialEq)]
pub struct PublicKey {
    pub n: BigUint,
    pub e: BigUint,
}

#[derive(Clone, PartialEq)]
pub struct PrivateKey {
    pub n: BigUint,
    pub d: BigUint,
}

impl From<&Generator> for PublicKey {
    fn from(value: &Generator) -> Self {
        PublicKey {
            n: value.n.clone(),
            e: value.e.clone(),
        }
    }
}

impl From<&Path> for PublicKey {
    fn from(path: &Path) -> Self {
        let decode = |text: String| general_purpose::STANDARD.decode(text.clone()).unwrap();

        let pk_path = path.to_str().unwrap();
        match File::open(&pk_path) {
            Ok(file) => {
                let mut lines = vec![];
                for line in BufReader::new(file).lines() {
                    lines.push(line.expect("Fail in reading file"));
                }

                let n = BigUint::from_radix_be(
                    str::from_utf8(&decode(lines.remove(1))).unwrap().as_bytes(),
                    16u32,
                )
                .unwrap();
                let e = BigUint::from_radix_be(
                    str::from_utf8(&decode(lines.remove(1))).unwrap().as_bytes(),
                    16u32,
                )
                .unwrap();

                let pk = PublicKey::new(&n, &e).unwrap();
                return pk;
            }
            Err(_) => panic!("Fail to load Public Key from path: {}", pk_path),
        };
    }
}

impl PublicKey {
    pub fn new(_n: &BigUint, _e: &BigUint) -> Result<Self> {
        Ok(PublicKey {
            n: _n.to_owned(),
            e: _e.to_owned(),
        })
    }

    pub fn encrypt_plain(&self, msg: &str) -> Result<BigUint> {
        if !msg.is_ascii() {
            Err(Error::MessageNotASCII)
        } else {
            let msg_code: BigUint = BigUint::from_bytes_be(msg.as_bytes());
            Ok(msg_code.modpow(&self.e, &self.n))
        }
    }

    pub fn encrypt(&self, msg: &str) -> Result<String> {
        if !msg.is_ascii() {
            Err(Error::MessageNotASCII)
        } else {
            let msg_code: BigUint = BigUint::from_bytes_be(msg.as_bytes());
            Ok(format!(
                "{}",
                msg_code.modpow(&self.e, &self.n).to_str_radix(16u32)
            ))
        }
    }
}

impl From<&Generator> for PrivateKey {
    fn from(value: &Generator) -> Self {
        PrivateKey {
            n: value.n.clone(),
            d: value.d.clone(),
        }
    }
}
impl From<&Path> for PrivateKey {
    fn from(path: &Path) -> Self {
        let decode = |text: String| general_purpose::STANDARD.decode(text.clone()).unwrap();

        let sk_path = path.to_str().unwrap();
        match File::open(&sk_path) {
            Ok(file) => {
                let mut lines = vec![];
                for line in BufReader::new(file).lines() {
                    lines.push(line.expect("Fail in reading file"));
                }

                let n = BigUint::from_radix_be(
                    str::from_utf8(&decode(lines.remove(1))).unwrap().as_bytes(),
                    16u32,
                )
                .unwrap();
                let e = BigUint::from_radix_be(
                    str::from_utf8(&decode(lines.remove(1))).unwrap().as_bytes(),
                    16u32,
                )
                .unwrap();

                let sk = PrivateKey::new(&n, &e).unwrap();
                return sk;
            }
            Err(_) => panic!("Fail to load Public Key from path: {}", sk_path),
        };
    }
}

impl PrivateKey {
    pub fn new(_n: &BigUint, _d: &BigUint) -> Result<Self> {
        Ok(PrivateKey {
            n: _n.to_owned(),
            d: _d.to_owned(),
        })
    }

    pub fn decrypt_plain(&self, ciphertext: &str) -> Result<BigUint> {
        let c: BigUint = BigUint::from_str_radix(ciphertext, 16u32).unwrap();
        let decrypt_plain = c.modpow(&self.d, &self.n);
        Ok(decrypt_plain)
    }

    pub fn decrypt(&self, ciphertext: &str) -> Result<String> {
        let c: BigUint = BigUint::from_str_radix(ciphertext, 16u32).unwrap();
        let decrypt_as_bytes: Vec<u8> = c.modpow(&self.d, &self.n).to_bytes_be();
        let res_decrypt: &str = std::str::from_utf8(&decrypt_as_bytes).unwrap();
        Ok(format!("{}", res_decrypt))
    }
}
