use crate::{asn1::RSAPublicKey, rsa::primitives::i2osp};
use asn1_rs::{BigInt, BigUint};
use rand::{thread_rng, RngCore};

use super::primitives::{os2ip, rsaep};

pub type RSAEncryptionResult = Result<Vec<u8>, String>;

pub fn rsaes_pkcs1_v1_5_encrypt(recipient: RSAPublicKey, message: &[u8]) -> RSAEncryptionResult {
    if message.len() <= recipient.modulus.to_bytes_be().len() - 11 {
        let ps_length = recipient.modulus.to_bytes_be().len() - message.len() - 3;

        let mut ps = Vec::with_capacity(ps_length);
        thread_rng().fill_bytes(&mut ps);

        let mut em: Vec<u8> = Vec::new();

        let mut message = Vec::from(message);
        em.push(0x00);
        em.push(0x02);
        em.append(&mut ps);
        em.push(0x00);
        em.append(&mut message);

        println!("{:?}", &em);
        let integer_message = os2ip(&em);

        let integer_ciphertext = rsaep(&recipient, integer_message);

        let cipher_text = i2osp(
            integer_ciphertext,
            recipient.modulus.clone().to_bytes_be().len(),
        );

        Ok(cipher_text)
    } else {
        Err("message too long".into())
    }
}

/*
fn rsaes_oaep_encrypt(recipient: RSAPublicKey, message: &[u8], label: &[u8]) {

}
 */
