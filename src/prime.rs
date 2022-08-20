use num_bigint::{BigUint, RandBigInt};
use rand::thread_rng;

pub fn generate_prime(bitsize: u32) -> BigUint {
    loop {
        let mut rng = thread_rng();
        let val: BigUint = rng.gen_biguint_range(
            &((BigUint::new(vec![2]).pow(bitsize - 1)) + 1 as u64),
            &((BigUint::new(vec![2]).pow(bitsize)) - 1 as u64),
        );

        if is_prime(&val) {
            break val;
        }
    }
}

pub fn is_prime(number: &BigUint) -> bool {
    //# of Testing rounds
    let k = 5;

    // Corner cases
    if number <= &BigUint::from(1u64) || number == &BigUint::from(4u64) {
        return false;
    };
    if number <= &BigUint::from(3u64) {
        return true;
    };

    // Find r such that n = 2^d * r + 1 for some r >= 1
    let mut d: BigUint = number.clone() - 1 as u64;
    while &d % 2 as u64 == BigUint::from(0u64) {
        d /= 2 as u64;
    }

    for _i in 0..k {
        if miller_rabin(&d, number) == Primality::Composite {
            return false;
        }
    }

    return true;
}

pub fn miller_rabin(d: &BigUint, number: &BigUint) -> Primality {
    let mut d = d.clone();

    let mut rng = thread_rng();
    // Pick a random number in [2..n-2]
    // Corner cases make sure that n > 4
    let random_int: BigUint =
        rng.gen_biguint_range(&BigUint::from(2 as u64), &(number.clone() - (2 as u64)));

    // Compute a^d % n
    let mut x = random_int.modpow(&d, number);

    if x == BigUint::from(1u64) || x == number - BigUint::from(1u64) {
        return Primality::ProbablyPrime;
    }

    // Keep squaring x while one of the following doesn't
    // happen
    // (i)   d does not reach n-1
    // (ii)  (x^2) % n is not 1
    // (iii) (x^2) % n is not n-1
    while d != number - 1u64 {
        x = (x.clone() * x.clone()) % number;
        d *= 2u64;

        if x == BigUint::from(1u64) {
            return Primality::Composite;
        };
        if x == number - 1u64 {
            return Primality::ProbablyPrime;
        };
    }

    return Primality::Composite;
}

#[derive(PartialEq)]
pub enum Primality {
    ProbablyPrime,
    Composite,
}
