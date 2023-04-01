use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Sample};
use plonky2_ecdsa::curve::{
    curve_types::AffinePoint,
    ecdsa::{ECDSAPublicKey, ECDSASecretKey},
    secp256k1::Secp256K1,
};

type Curve = Secp256K1;

pub fn generate_secret_key() -> ECDSASecretKey<Curve> {
    ECDSASecretKey::<Curve>(Secp256K1Scalar::rand())
}

pub fn to_canonical_pubkey(pubkey: ECDSAPublicKey<Curve>) {
    // AffinePoint::from(value)
}

fn bytes_to_u32_array(bytes: &[u8; 20]) -> [u32; 10] {
    let mut arr = [0u32; 10];
    for i in 0..10 {
        arr[i] = u32::from_be_bytes([
            bytes[i * 4],
            bytes[i * 4 + 1],
            bytes[i * 4 + 2],
            bytes[i * 4 + 3],
        ]);
    }
    arr
}

fn u32_array_to_bytes(arr: &[u32; 8]) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    for (i, item) in arr.iter().enumerate() {
        bytes[i * 4..i * 4 + 4].copy_from_slice(&item.to_be_bytes());
    }
    bytes
}
