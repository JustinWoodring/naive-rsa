use std::{thread, time::Duration};

use asn1_rs::BigUint;
use log::debug;

use crate::{
    asn1::{RSAPrivateKey, RSAPublicKey},
    math::{lcm, mod_inverse},
    prime::generate_prime,
};

pub fn generate_keypair(bitsize: u32) -> RSAPrivateKey {
    let bits = bitsize;

    let (p, q, n, carmichael_totient, e) = loop {
        let mut p_handle = thread::spawn(move || {
            let p = generate_prime(bits / 2);
            log::debug!("Found p: {}", p);
            p
        });

        let mut q_handle = thread::spawn(move || {
            let q = generate_prime(bits / 2);
            log::debug!("Found q: {}", q);
            q
        });

        let mut p = BigUint::from(0u64);
        let mut q = BigUint::from(0u64);

        loop {
            if p_handle.is_finished() && q_handle.is_finished() {
                p = p_handle.join().unwrap();
                q = q_handle.join().unwrap();
                break;
            }

            thread::sleep(Duration::from_millis(500));
        }

        let n = &p * &q;
        log::debug!("Computed n: {}", n);

        let carmichael_totient = lcm(&(p.clone() - 1u64), &(q.clone() - 1u64));

        log::debug!(
            "Computed carmichael totient of p - 1 and n - 1: {}",
            carmichael_totient
        );

        let e = BigUint::from(65537u64);
        if &carmichael_totient % &e != BigUint::from(0u64) {
            break (p, q, n, carmichael_totient, e);
        } else {
            debug!("Oh noez vulnerable e regenerating keys.");
        }
    };

    log::debug!("Found e {}", e);

    let d = BigUint::try_from(mod_inverse(
        &e.clone().into(),
        &carmichael_totient.clone().into(),
    ))
    .expect("decryption constant is messed up");

    log::debug!("Found d {}", d);

    let private_key = RSAPrivateKey {
        version: BigUint::from(0u64),
        modulus: n.clone(),
        public_exponent: e.clone(),                // e
        private_exponent: d.clone(),               // d
        prime1: p.clone(),                         // p
        prime2: q.clone(),                         // q
        exponent1: d.clone() % (p.clone() - 1u64), // d mod (p-1)
        exponent2: d % (q.clone() - 1u64),         // d mod (q-1)
        coefficient: BigUint::try_from(mod_inverse(&(q.clone()).into(), &(p.clone()).into()))
            .expect("coefficient calculation messed up."), // (inverse of q) mod p
    };

    private_key
}
