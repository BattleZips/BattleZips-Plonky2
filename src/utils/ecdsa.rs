use plonky2::field::secp256k1_scalar::Secp256K1Scalar;
use plonky2_ecdsa::curve::{
    curve_types::{Curve, CurveScalar},
    ecdsa::{sign_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};

pub fn keypair() -> (SecretKey, PublicKey) {
    let mut rng = rand::thread_rng();
    let sk = ECDSASecretKey::<Secp256K1>(Secp256K1Scalar::rand());
    let pk = ECDSAPublicKey((CurveScalar(sk.0) * Curve::GENERATOR_PROJECTIVE).to_affine());
    (sk, pk)
}

pub fn sign(msg: Secp256K1Scalar, sk: ECDSASecretKey<Secp256K1>) -> ECDSASignature<Secp256K1> {
    sign_message(msg, sk)
}
