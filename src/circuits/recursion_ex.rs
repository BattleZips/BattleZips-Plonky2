// use plonky2::{
//     field::{extension::Extendable, goldilocks_field::GoldilocksField},
//     hash::hash_types::RichField,
//     iop::witness::{PartialWitness, WitnessWrite},
//     plonk::{
//         circuit_builder::CircuitBuilder,
//         circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
//         config::{GenericConfig, PoseidonGoldilocksConfig},
//         proof::ProofWithPublicInputs,
//     },
// };

// fn make_first_proof<F, C, const D: usize>(
// ) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
// where
//     F: RichField + Extendable<D>,
//     C: GenericConfig<D, F = F>,
// {
//     let mut config = CircuitConfig::standard_recursion_config();
//     config.zero_knowledge = false;

//     // First proof that "x satisfies x^2 = 4"
//     let mut builder = CircuitBuilder::<F, D>::new(config.clone());
//     let x_t = builder.add_virtual_target();
//     builder.register_public_input(x_t); // Register x as public input
//     let x2_t = builder.exp_u64(x_t, 2);
//     let four_t = builder.constant(F::from_canonical_u64(4));
//     builder.connect(x2_t, four_t);

//     let data = builder.build::<C>();
//     let mut pw = PartialWitness::<F>::new();
//     pw.set_target(x_t, F::from_canonical_u64(2)); // x = 2
//     let proof = data.prove(pw)?;
//     data.verify(proof.clone())?;
//     Ok((data.verifier_data(), proof))
// }

use crate::{
    circuits::shot::ShotCircuit,
    utils::{board::Board, ship::Ship},
};

use num::bigint::BigUint;

use anyhow::Result;
use plonky2::field::{
    secp256k1_scalar::Secp256K1Scalar,
    types::{Field, Sample},
};
use plonky2_ecdsa::curve::{
    curve_types::Curve as TCurve,
    ecdsa::{sign_message, verify_message, ECDSAPublicKey, ECDSASecretKey, ECDSASignature},
    secp256k1::Secp256K1,
};

type Curve = Secp256K1;
type PublicKey = ECDSAPublicKey<Curve>;
type MessageHash = <Curve as TCurve>::ScalarField;
type Signature = ECDSASignature<Curve>;

fn biguint_from_array(arr: [u64; 4]) -> BigUint {
    BigUint::from_slice(&[
        arr[0] as u32,
        (arr[0] >> 32) as u32,
        arr[1] as u32,
        (arr[1] >> 32) as u32,
        arr[2] as u32,
        (arr[2] >> 32) as u32,
        arr[3] as u32,
        (arr[3] >> 32) as u32,
    ])
}

fn make_shot_proof() {
    type Field = <Curve as TCurve>::ScalarField;
    let shot_circuit = ShotCircuit::new().unwrap();
    // define inputs
    let board = Board::new(
        Ship::new(3, 4, false),
        Ship::new(9, 6, true),
        Ship::new(0, 0, false),
        Ship::new(0, 6, false),
        Ship::new(6, 1, true),
    );
    let shot = [0, 0];
    let shot_proof = shot_circuit.prove(board.clone(), shot).unwrap();
    let output = ShotCircuit::decode_public(shot_proof.clone()).unwrap();
    let commitment = output.commitment;
    let secret_key = ECDSASecretKey::<Curve>(Secp256K1Scalar::rand());
    let public_key = secret_key.to_public();
    println!("Pub key: {:?}", public_key.0.x);
    let int = biguint_from_array(commitment);
    let msg = Secp256K1Scalar::from_noncanonical_biguint(int);
    let signature = sign_message(msg, secret_key);
    let verified = verify_message(msg, signature, public_key);
    println!("Verified: {}", verified.to_string());
}

fn main() -> Result<()> {
    make_shot_proof();
    // const D: usize = 2;
    // type F = GoldilocksField;
    // type C = PoseidonGoldilocksConfig;

    // let (verifier_data, proof) = make_first_proof::<F, C, D>()?;
    // println!("First proof passed!");

    // Recursive proof
    // let mut config = CircuitConfig::standard_recursion_config();
    // config.zero_knowledge = true;

    // let mut builder = CircuitBuilder::<F, D>::new(config);

    // let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    // builder.register_public_inputs(&proof_t.public_inputs); // register first proof's public input

    // let constants_sigmas_cap_t =
    //     builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);

    // let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    // let verifier_circuit_t = VerifierCircuitTarget {
    //     constants_sigmas_cap: constants_sigmas_cap_t,
    //     circuit_digest: circuit_digest_t,
    // };

    // builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    // let mut pw = PartialWitness::<F>::new();
    // pw.set_proof_with_pis_target(&proof_t, &proof);
    // let data = builder.build::<C>();
    // let proof_recursive = data.prove(pw)?;
    // data.verify(proof_recursive.clone())?;

    // println!("Recursive proof passed!");
    // println!("public inputs :{:?}", proof_recursive.public_inputs);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test() {
        main().unwrap();
    }
}
