use plonky2::field::{secp256k1_scalar::Secp256K1Scalar, types::Sample};
use plonky2_ecdsa::curve::{
    curve_types::AffinePoint,
    ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};
use sha3::{Digest, Keccak256};

type Curve = Secp256K1;

pub fn generate_secret_key() -> ECDSASecretKey<Curve> {
    ECDSASecretKey::<Curve>(Secp256K1Scalar::rand())
}

pub fn pubkey_to_eth_address(pubkey: ECDSAPublicKey<Curve>) {
    let x = pubkey.0.x.to_string();
    let y = pubkey.0.y.to_string();

    let mut combined: [u8; 64] = [0; 64];
    combined[..32].copy_from_slice(x.as_bytes());
    combined[32..].copy_from_slice(y.as_bytes());

    let hash = Keccak256::digest(combined);

    let address = &hash[hash.len() - 20..];

    let address_hex = hex::encode(address);
    println!("{:?}", address_hex);
}

pub fn to_canonical_pubkey(pubkey: ECDSAPublicKey<Curve>) {
    // AffinePoint::from(value)
}

// fn bytes_to_u32_array(bytes: &[u8; 20]) -> [u32; 10] {
//     let mut arr = [0u32; 10];
//     for i in 0..10 {
//         arr[i] = u32::from_be_bytes([
//             bytes[i * 4],
//             bytes[i * 4 + 1],
//             bytes[i * 4 + 2],
//             bytes[i * 4 + 3],
//         ]);
//     }
//     arr
// }

// fn u32_array_to_bytes(arr: &[u32; 8]) -> [u8; 32] {
//     let mut bytes = [0u8; 32];
//     for (i, item) in arr.iter().enumerate() {
//         bytes[i * 4..i * 4 + 4].copy_from_slice(&item.to_be_bytes());
//     }
//     bytes
// }

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_secret_key_generation() {
        let secret_key = generate_secret_key();
        println!("Secret key: {:?}", secret_key);
    }

    #[test]
    fn test_public_key_to_eth_address() {
        let secret_key = generate_secret_key();
        let pubkey = secret_key.to_public();
        // let msg = Secp256K1Scalar::rand();
        // let signature = sign_message(msg, secret_key);
        pubkey_to_eth_address(pubkey);
    }
}
