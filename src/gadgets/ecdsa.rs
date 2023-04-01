use crate::circuits::{D, F};

use plonky2::{
    field::{
    extension::FieldExtension,
    secp256k1_scalar::Secp256K1Scalar,
    types::{Sample},
    },
    iop::target::Target,
    plonk::circuit_builder::CircuitBuilder
};

use anyhow::Result;

use num::bigint::BigUint;

use plonky2_ecdsa::{
    curve::{
        curve_types::Curve,
        ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
        secp256k1::Secp256K1,
    },
    gadgets::{
        ecdsa::{ECDSAPublicKeyTarget, ECDSASignatureTarget, verify_message_circuit},
        nonnative::{CircuitBuilderNonNative, NonNativeTarget},
        curve::CircuitBuilderCurve,
        biguint::{CircuitBuilderBiguint, BigUintTarget},
    }
};

pub fn verify_board_signature(board: [Target; 4], builder: &mut CircuitBuilder<F, D>,) -> Result<ECDSASignatureTarget<Secp256K1>> {

    let message = builder.add_virtual_biguint_target(num_limbs);

    let pubkey = ECDSAPublicKeyTarget::<Secp256K1>(builder.add_virtual_affine_point_target());
    let signature = ECDSASignatureTarget {
        r: builder.add_virtual_nonnative_target(),
        s: builder.add_virtual_nonnative_target(),
    };
    verify_message_circuit(builder, msg, sig, pk);

    // });
    // let config = CircuitConfig::standard_ecc_config();
    // let pw = PartialWitness::new();
    // let mut builder = CircuitBuilder::<F, D>::new(config);
    // let msg = Secp256K1Scalar::rand();

}