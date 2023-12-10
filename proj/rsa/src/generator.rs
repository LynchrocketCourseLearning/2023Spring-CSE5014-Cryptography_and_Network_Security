use base64::{engine::general_purpose, Engine};
use num::{One, Signed};
use num_bigint::{BigInt, BigUint, RandBigInt, Sign};
use rand;
use std::{fmt::Display, fs::File, io::Write, str, thread};

use crate::{
    algorithms::{ext_euc, is_prime},
    plain_rsa::{PublicKey, PrivateKey},
    errors::Result,
};

pub struct Generator {
    pub n: BigUint,
    pub e: BigUint,
    pub d: BigUint,
}

impl Display for Generator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "n: {}, e: {}, d: {}", &self.n, &self.e, &self.d)
    }
}

impl From<(&PublicKey, &PrivateKey)> for Generator {
    fn from((pk, sk): (&PublicKey, &PrivateKey)) -> Self {
        if pk.n != sk.n {
            panic!("Invalid public key and secret key pair.")
        } else {
            Generator {
                n: pk.n.clone(),
                e: pk.e.clone(),
                d: sk.d.clone(),
            }
        }
    }
}

impl Generator {
    pub fn new(size: u64) -> Result<Self> {
        let q_spawn = thread::spawn(move || Self::new_prime(size));
        let p: BigUint = Self::new_prime(size);
        let q: BigUint = q_spawn.join().unwrap();
        let n: BigUint = &p * &q;
        let fi_n: BigUint = (&p - BigUint::one()) * (&q - BigUint::one());

        let e: BigUint = BigUint::from(65537 as u64);
        let (mut s, _, _) = ext_euc(
            &BigInt::from_biguint(Sign::Plus, e.clone()),
            &BigInt::from_biguint(Sign::Plus, fi_n.clone()),
        );

        while s.is_negative() {
            s += BigInt::from_biguint(Sign::Plus, fi_n.clone());
        }
        let d: BigUint = s.to_biguint().unwrap();

        Ok(Generator { n, e, d })
    }

    pub fn new_prime(size: u64) -> BigUint {
        let mut rng = rand::thread_rng();
        loop {
            let proposal: BigUint = rng.gen_biguint(size);
            if is_prime(&proposal) == true {
                return proposal;
            }
        }
    }

    pub fn print_to_file(&self) -> Result<()> {
        let mut pk_file = File::create("rsa_pk.key").unwrap();
        let mut sk_file = File::create("rsa_sk.key").unwrap();

        let encode =
            |msg: &BigUint| general_purpose::STANDARD.encode(msg.to_owned().to_radix_be(16u32));

        let (mut pk, mut sk) = (String::new(), String::new());
        pk.push_str("---------- BEGIN RSA PUBLIC KEY ----------");
        pk.push_str("\n");
        pk.push_str(str::from_utf8(encode(&self.n).as_bytes()).unwrap());
        pk.push_str("\n");
        pk.push_str(str::from_utf8(encode(&self.e).as_bytes()).unwrap());
        pk.push_str("\n");
        pk.push_str("----------- END RSA PUBLIC KEY -----------");

        sk.push_str("---------- BEGIN RSA PRIVATE KEY ----------");
        sk.push_str("\n");
        sk.push_str(str::from_utf8(encode(&self.n).as_bytes()).unwrap());
        sk.push_str("\n");
        sk.push_str(str::from_utf8(encode(&self.d).as_bytes()).unwrap());
        sk.push_str("\n");
        sk.push_str("----------- END RSA PRIVATE KEY -----------");

        pk_file.write_all(pk.as_bytes()).unwrap();
        sk_file.write_all(sk.as_bytes()).unwrap();
        Ok(())
    }
}

