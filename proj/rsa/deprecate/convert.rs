use crate::errors::{Error, Result};
use num_bigint::{BigUint, ToBigUint};
use num_traits::{FromPrimitive, ToPrimitive, Zero};

pub fn i2osp(x: &BigUint, size: usize) -> Result<Vec<u8>> {
    if size == 0 {
        return Err(Error::IntergerTooLarge);
    }

    let mut _x: BigUint = x.clone();
    let mut output: Vec<u8> = vec![0_u8; size];
    for i in 0..size {
        output[size - i - 1] = (&_x & &BigUint::from_u8(0xff).unwrap()).to_u8().unwrap();
        _x >>= 8;
    }

    if _x.is_zero() {
        Ok(output)
    } else {
        Err(Error::IntergerTooLarge)
    }
}

pub fn os2ip(x: &[u8]) -> Result<BigUint> {
    if x.len() == 0 {
        return Err(Error::OctetStringEmpty);
    }

    let mut output: BigUint = BigUint::zero();
    for i in x {
        output <<= u8::BITS;
        output += i.to_biguint().unwrap();
    }

    Ok(output)
}

pub fn string_xor(a: &[u8], b: &[u8]) -> Result<Vec<u8>> {
    // if a.len() != b.len() {
    //     return Err(Error::InvalidBufferSize);
    // }

    let mut output: Vec<u8> = a.to_vec();
    let mut another = b.to_vec();
    if a.len() > b.len() {
        output = b.to_vec();
        another = a.to_vec();
    }
    for i in 0..output.len() {
        output[i] ^= another[i];
    }

    Ok(output)
}
