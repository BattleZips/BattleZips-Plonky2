

use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField},
    hash::hash_types::RichField,
    iop::witness::{PartialWitness, WitnessWrite},
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

fn make_first_proof<F, C, const D: usize>(
) -> Result<(VerifierCircuitData<F, C, D>, ProofWithPublicInputs<F, C, D>)>
where
    F: RichField + Extendable<D>,
    C: GenericConfig<D, F = F>,
{
    let mut config = CircuitConfig::standard_recursion_config();
    config.zero_knowledge = false;

    // First proof that "x satisfies x^2 = 4"
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let x_t = builder.add_virtual_target();
    builder.register_public_input(x_t); // Register x as public input
    let x2_t = builder.exp_u64(x_t, 2);
    let four_t = builder.constant(F::from_canonical_u64(4));
    builder.connect(x2_t, four_t);

    let data = builder.build::<C>();
    let mut pw = PartialWitness::<F>::new();
    pw.set_target(x_t, F::from_canonical_u64(2)); // x = 2
    let proof = data.prove(pw)?;
    data.verify(proof.clone())?;
    Ok((data.verifier_data(), proof))
}

fn main() -> Result<()> {
    const D: usize = 2;
    type F = GoldilocksField;
    type C = PoseidonGoldilocksConfig;

    let (verifier_data, proof) = make_first_proof::<F, C, D>()?;
    println!("First proof passed!");

    // Recursive proof
    let mut config = CircuitConfig::standard_recursion_config();
    config.zero_knowledge = true;

    let mut builder = CircuitBuilder::<F, D>::new(config);

    let proof_t = builder.add_virtual_proof_with_pis(&verifier_data.common);
    builder.register_public_inputs(&proof_t.public_inputs); // register first proof's public input

    let constants_sigmas_cap_t =
        builder.constant_merkle_cap(&verifier_data.verifier_only.constants_sigmas_cap);

    let circuit_digest_t = builder.constant_hash(verifier_data.verifier_only.circuit_digest);
    let verifier_circuit_t = VerifierCircuitTarget {
        constants_sigmas_cap: constants_sigmas_cap_t,
        circuit_digest: circuit_digest_t,
    };

    builder.verify_proof::<C>(&proof_t, &verifier_circuit_t, &verifier_data.common);

    let mut pw = PartialWitness::<F>::new();
    pw.set_proof_with_pis_target(&proof_t, &proof);
    let data = builder.build::<C>();
    let proof_recursive = data.prove(pw)?;
    data.verify(proof_recursive.clone())?;

    println!("Recursive proof passed!");
    println!("public inputs :{:?}", proof_recursive.public_inputs);
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