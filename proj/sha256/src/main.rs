const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

const ROUND_CONSTANTS: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn rightrotate32(x: u32, n: u32) -> u32 {
    (x >> (n % 32)) | (x << ((32 - n) % 32))
}

fn big_sigma0(x: u32) -> u32 {
    rightrotate32(x, 2) ^ rightrotate32(x, 13) ^ rightrotate32(x, 22)
}

fn big_sigma1(x: u32) -> u32 {
    rightrotate32(x, 6) ^ rightrotate32(x, 11) ^ rightrotate32(x, 25)
}

fn low_sigma0(x: u32) -> u32 {
    rightrotate32(x, 7) ^ rightrotate32(x, 18) ^ (x >> 3)
}

fn low_sigma1(x: u32) -> u32 {
    rightrotate32(x, 17) ^ rightrotate32(x, 19) ^ (x >> 10)
}

fn padding(length: u64) -> Vec<u8> {
    let mut padding_bytes = vec![0x80];
    let remainder_bytes = (length + 8) % 64;
    let filler_bytes = 64 - remainder_bytes;
    let zero_bytes = filler_bytes - 1;
    for _ in 0..zero_bytes {
        padding_bytes.push(0);
    }
    padding_bytes.extend_from_slice(&(8 * length).to_be_bytes());
    padding_bytes
}

fn message_schedule(block: &[u8; 64]) -> [u32; 64] {
    let mut w = [0; 64];
    for i in 0..16 {
        w[i] = u32::from_be_bytes(block[4 * i..][..4].try_into().unwrap());
    }
    for i in 16..64 {
        w[i] = w[i - 16]
            .wrapping_add(low_sigma0(w[i - 15]))
            .wrapping_add(w[i - 7])
            .wrapping_add(low_sigma1(w[i - 2]));
    }
    w
}

fn choice(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (!x & z)
}

fn majority(x: u32, y: u32, z: u32) -> u32 {
    (x & y) ^ (x & z) ^ (y & z)
}

fn round(state: &[u32; 8], round_constant: u32, schedule_word: u32) -> [u32; 8] {
    let ch = choice(state[4], state[5], state[6]);
    let tmp1 = state[7]
        .wrapping_add(big_sigma1(state[4]))
        .wrapping_add(ch)
        .wrapping_add(round_constant)
        .wrapping_add(schedule_word);
    let maj = majority(state[0], state[1], state[2]);
    let tmp2 = big_sigma0(state[0]).wrapping_add(maj);
    [
        tmp1.wrapping_add(tmp2),
        state[0],
        state[1],
        state[2],
        state[3].wrapping_add(tmp1),
        state[4],
        state[5],
        state[6],
    ]
}

fn compress(origin_state: &[u32; 8], block: &[u8; 64]) -> [u32; 8] {
    let w = message_schedule(block);
    let mut state = *origin_state;
    for i in 0..64 {
        state = round(&state, ROUND_CONSTANTS[i], w[i]);
    }
    [
        origin_state[0].wrapping_add(state[0]),
        origin_state[1].wrapping_add(state[1]),
        origin_state[2].wrapping_add(state[2]),
        origin_state[3].wrapping_add(state[3]),
        origin_state[4].wrapping_add(state[4]),
        origin_state[5].wrapping_add(state[5]),
        origin_state[6].wrapping_add(state[6]),
        origin_state[7].wrapping_add(state[7]),
    ]
}

fn get_hash(state: &[u32; 8]) -> [u8; 32] {
    let mut hash = [0; 32];
    for i in 0..8 {
        hash[4 * i..][..4].copy_from_slice(&state[i].to_be_bytes());
    }
    hash
}

fn sha256(message: &[u8]) -> [u8; 32] {
    let mut padded_message = message.to_vec();
    padded_message.extend_from_slice(&padding(message.len() as u64));
    assert_eq!(0, padded_message.len() % 64);
    let mut state = IV;
    for block in padded_message.chunks(64) {
        state = compress(&state, block.try_into().unwrap());
    }
    get_hash(&state)
}

fn main() {}

#[test]
fn test_sha256() {
    // The sha2 dependency is only used right here, for testing.
    use sha2::{Digest, Sha256};
    for i in 0..1000 {
        dbg!(i);
        let input = vec![i as u8; i];
        let my_hash = sha256(&input);
        let mut standard_hasher = Sha256::new();
        standard_hasher.update(&input);
        let expected = standard_hasher.finalize();
        assert_eq!(my_hash[..], expected[..]);
    }
}
