use asn1_rs::BigInt;

use crate::asn1::RSAPublicKey;

pub fn os2ip(message: &[u8]) -> BigInt {
    let mut result = BigInt::from(0u32);
    for i in 1..message.len() {
        result += BigInt::from(message[message.len() - i].to_owned())
            * BigInt::from(256u32).pow((message.len() - i).try_into().unwrap())
    }

    result
}

pub fn rsaep(recipient: &RSAPublicKey, integer_message: BigInt) -> BigInt {
    let integer_ciphertext = integer_message.modpow(
        &BigInt::from(recipient.public_exponent.clone()),
        &BigInt::from(recipient.modulus.clone()),
    );

    integer_ciphertext
}

pub fn i2osp(message: BigInt, message_length: usize) -> Vec<u8> {
    let mut message = message.clone();
    let mut result: Vec<u8> = Vec::new();
    for i in 1..=message_length {
        let message_section =
            message.clone() / BigInt::from(256i32).pow((message_length - i).try_into().unwrap());
        message =
            message.clone() % BigInt::from(256i32).pow((message_length - i).try_into().unwrap());
        result.push(message_section.try_into().unwrap());
    }

    result.reverse();
    result
}
