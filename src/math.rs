use num_bigint::{BigInt, BigUint};

pub fn mod_inverse(a: &BigInt, m: &BigInt) -> BigInt {
    let mut a = a.clone();
    let mut m = m.clone();
    let m0 = m.clone();
    let mut y = BigInt::from(0u64);
    let mut x = BigInt::from(1u64);

    if m == BigInt::from(1u64) {
        return BigInt::from(0u64);
    }

    while a > BigInt::from(1u64) {
        // q is quotient
        let q = &a / &m;
        let mut t = m.clone();

        // m is remainder now, process same as
        // Euclid's algo
        m = a % &m;
        a = t;
        t = y.clone();

        // Update y and x
        y = x - q * &y;
        x = t;
    }

    // Make x positive
    if x < BigInt::from(0u64) {
        x += m0;
    }

    return x;
}

pub fn lcm(a: &BigUint, b: &BigUint) -> BigUint {
    a * (b / gcd(a, b))
}

pub fn gcd(a: &BigUint, b: &BigUint) -> BigUint {
    let mut a: BigUint = a.clone();
    let mut b: BigUint = b.clone();

    let mut d = 0;

    loop {
        //a and b eqal
        if &a == &b {
            //debug!("equal");
            return &a * BigUint::from(2u64).pow(d);
        //a is even and b is even
        } else if &a % 2u64 == BigUint::from(0u64) && &b % 2u64 == BigUint::from(0u64) {
            //debug!("a and b are even, d = {}", d);
            a = &a / 2u64;
            b = &b / 2u64;
            d += 1;
        //a is even and b is odd
        } else if &a % 2u64 == BigUint::from(0u64) && &b % 2u64 != BigUint::from(0u64) {
            //debug!("a is even b is odd");
            a = &a / 2u64;
        //a is odd and b is even
        } else if &a % 2u64 != BigUint::from(0u64) && &b % 2u64 == BigUint::from(0u64) {
            //debug!("a is odd b is even");
            b = &b / 2u64;
        //a is odd and b is odd
        } else if &a % 2u64 != BigUint::from(0u64) && &b % 2u64 != BigUint::from(0u64) {
            //debug!("a and b are odd");
            if &a < &b {
                let temp = a.clone();
                a = b;
                b = temp;
            }

            let c = &a - &b;
            a = c / 2u64;
        }
    }
}
