use num::{Integer, One, ToPrimitive, Zero};
use num_bigint::{BigInt, BigUint, RandBigInt};
use rand;

// Extended Euclidean Algorithm
// Returns Bezout's identity coefficients and gcd(a,b)
// as + bt = gcd(a,b)
pub fn ext_euc(a: &BigInt, b: &BigInt) -> (BigInt, BigInt, BigInt) {
    let (mut r1, mut r2) = (a.clone(), b.clone());
    if r1.is_zero() || r2.is_zero() {
        (r1.clone() ^ r2.clone(), BigInt::zero(), BigInt::one())
    } else {
        let (mut s1, mut s2) = (BigInt::one(), BigInt::zero());
        let (mut t1, mut t2) = (BigInt::zero(), BigInt::one());
        while !r2.is_zero() {
            let q = &r1 / &r2;
            (r1, r2) = (r2.clone(), (r1 - &q * r2));
            (s1, s2) = (s2.clone(), (s1 - &q * s2));
            (t1, t2) = (t2.clone(), (t1 - &q * t2));
        }
        (s1, t1, r1)
    }
}

#[cfg(test)]
#[test]
fn test_ext_euc() {
    let a = BigInt::from(240);
    let b = BigInt::from(46);
    let (s, t, d) = ext_euc(&a, &b);
    assert!(s == BigInt::from(-9), "s = {}", s);
    assert!(t == BigInt::from(47), "t = {}", t);
    assert!(d == BigInt::from(2), "d = {}", d);
}

pub fn is_prime(proposal: &BigUint) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = &one + &one;

    if proposal.is_zero() || (proposal != &two && proposal.is_even()) {
        return false;
    }

    // less than 1/2 probability to find
    if !fermat_test(proposal) {
        return false;
    }

    const MILLER_RABIN_THRES: u64 = 8;
    miller_rabin_test(proposal, MILLER_RABIN_THRES)
}

fn fermat_test(proposal: &BigUint) -> bool {
    let mut rng = rand::thread_rng();

    let a: BigUint = rng.gen_biguint_below(proposal);
    a.modpow(&(proposal - BigUint::one()), proposal).is_one()
}

fn miller_rabin_test(proposal: &BigUint, threshold: u64) -> bool {
    let one: BigUint = BigUint::one();
    let two: BigUint = &one + &one;

    if proposal == &one {
        return false;
    } else if proposal == &two {
        return true;
    } else if proposal.is_even() {
        return false;
    }

    let mut d: BigUint = proposal - &one;
    let mut s: BigUint = BigUint::zero();
    while d.is_even() {
        d = d.div_floor(&two);
        s += &one;
    }

    let step: u64 = (s - &one).to_u64().unwrap();
    let mut rng = rand::thread_rng();
    for _ in 0..threshold {
        let a: BigUint = rng.gen_biguint_range(&two, &(proposal - &one));
        let mut x: BigUint = a.modpow(&d, &proposal);

        if x.is_one() || x == (proposal - &one) {
            continue;
        }

        let mut flag: bool = false;
        for _ in 0..step {
            x = x.modpow(&two, proposal);

            if x.is_one() {
                return false;
            } else if x == (proposal - &one) {
                // probably still not prime, check multiple times
                flag = true;
                break;
            }
        }

        if !flag {
            return false;
        }
    }
    true
}
