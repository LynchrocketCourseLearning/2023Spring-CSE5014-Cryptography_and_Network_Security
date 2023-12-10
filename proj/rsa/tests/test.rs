use my_rsa::*;

#[cfg(test)]
mod tests {
    use std::path::Path;

    use num_bigint::{BigInt, BigUint, Sign};
    use num_traits::Signed;

    use super::*;

    #[test]
    fn test_gen_keys() {
        let gen = generator::Generator::new(1024);
        match gen {
            Ok(v) => println!("Success:\n n: {:?},\n e: {:?},\n d: {:?}", v.n, v.e, v.d),
            Err(e) => println!("Error:\n {:?}", e),
        }
    }

    #[test]
    fn test_encrypt_decrypt() {
        // initialize the enc() and dec()
        let gen = generator::Generator::new(1024).unwrap();
        let enc = plain_rsa::PublicKey::from(&gen);
        let dec = plain_rsa::PrivateKey::from(&gen);

        assert_eq!(enc.n, dec.n);

        let msg = String::from("Hello World!");
        let ciphertext = enc.encrypt(&msg[..]).unwrap();
        let plaintext = dec.decrypt(&ciphertext[..]).unwrap();

        assert_eq!(&msg[..], &plaintext[..]);
        println!(
            "msg: {}, \nciphertext: {}, \nplaintext: {}",
            msg, ciphertext, plaintext
        );
    }

    #[test]
    fn test_to_from_file() {
        let gen = generator::Generator::new(1024).unwrap();
        let enc = plain_rsa::PublicKey::from(&gen);
        let dec = plain_rsa::PrivateKey::from(&gen);

        let res = gen.print_to_file();
        match res {
            Ok(_) => println!("Success"),
            Err(e) => println!("Error:\n {:?}", e),
        }

        let from_file_enc = plain_rsa::PublicKey::from(Path::new("rsa_pk.key"));
        let from_file_dec = plain_rsa::PrivateKey::from(Path::new("rsa_sk.key"));

        assert_eq!(from_file_enc.n, from_file_dec.n);

        assert_eq!(enc.n, from_file_enc.n);
        assert_eq!(enc.e, from_file_enc.e);

        assert_eq!(dec.n, from_file_dec.n);
        assert_eq!(dec.d, from_file_dec.d);
    }

    #[test]
    fn chosen_ciphertext_attack() {
        // initialize the oracle
        let gen = generator::Generator::new(1024).unwrap();
        let enc_oracle = plain_rsa::PublicKey::from(&gen);
        let dec_oracle = plain_rsa::PrivateKey::from(&gen);

        // secret_msg is not visible by the attacker but the attacker wants to reveal it from the ciphertext
        let secret_msg = BigUint::from_bytes_be("I am secret msg".as_bytes());
        let ciphertext = secret_msg.modpow(&enc_oracle.e, &enc_oracle.n);

        // the random multiplier
        let adder = BigUint::from_bytes_be("msg adder".as_bytes());
        let forge_ciphertext = ciphertext * adder.modpow(&enc_oracle.e, &enc_oracle.n);
        let forge_msg = forge_ciphertext.modpow(&dec_oracle.d, &dec_oracle.n);

        // compute the modular inverse of r modulo n
        let (mut adder_inv_module_n, _, _) = algorithms::ext_euc(
            &BigInt::from_biguint(num_bigint::Sign::Plus, adder.clone()),
            &BigInt::from_biguint(num_bigint::Sign::Plus, enc_oracle.n.clone()),
        );
        while adder_inv_module_n.is_negative() {
            adder_inv_module_n += BigInt::from_biguint(Sign::Plus, enc_oracle.n.clone());
        }

        // the secret_msg is revealed
        let adder_inv = adder_inv_module_n.to_biguint().unwrap();
        let retrieve_msg = forge_msg * adder_inv % enc_oracle.n;

        assert_eq!(retrieve_msg, secret_msg);
    }

    // #[test]
    // fn test_oaep() {
    //     let gen = my_rsa::generator::Generator::new(1024).unwrap();
    //     let enc = my_rsa::plain_rsa::PublicKey::from(&gen);
    //     let dec = my_rsa::plain_rsa::PrivateKey::from(&gen);

    //     assert_eq!(enc.n, dec.n);

    //     let msg = String::from("Hello World!");
    //     let label = String::from("my label");
    //     let ciphertext = oaep::oaep_encrypt_with_label(&enc, &msg, &label).unwrap();
    //     let plaintext = oaep::oaep_decrypt_with_label(&dec, &ciphertext, &label).unwrap();

    //     assert_eq!(&msg[..], std::str::from_utf8(&plaintext).unwrap());
    // }
}
