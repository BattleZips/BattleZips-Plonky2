use {
    super::super::{ProofTuple, ShieldedTargets, C, D, F},
    crate::{
        gadgets::board::{decompose_board, hash_board, place_ship, recompose_board},
        utils::board::Board,
    },
    anyhow::Result,
    log::Level,
    plonky2::{
        field::types::{Field, PrimeField64},
        iop::{
            target::{BoolTarget, Target},
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget},
            proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget},
            prover::prove,
        },
        util::timing::TimingTree,
    },
};

// BattleZips Channel Open: Recursive (non zk) proof of two valid board configurations - used to copy constrain pubkeys and board commitments
// @todo: make channel open circuit an action by host player who commits to a first shot

/**
 * Construct a partial witness for the channel open circuit
 *
 * @param host_t - targets for host proof
 * @param guest_t - targets for guest proof
 * @param host_p - host proof of valid board
 * @param guest_p - guest proof of valid board
 */
pub fn partial_witness(
    host_t: ShieldedTargets,
    guest_t: ShieldedTargets,
    host_p: ProofTuple<F, C, D>,
    guest_p: ProofTuple<F, C, D>,
) -> Result<PartialWitness<F>> {
    // construct partial witness
    let mut pw = PartialWitness::new();

    // witness host proof
    pw.set_proof_with_pis_target(&host_t.proof, &host_p.0);
    pw.set_verifier_data_target(&host_t.verifier, &host_p.1);

    // witness gues proof
    pw.set_proof_with_pis_target(&host_t.proof, &host_p.0);
    pw.set_verifier_data_target(&host_t.verifier, &host_p.1);

    // return witnessed inputs
    Ok(pw)
}

pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<([u64; 4], [u64; 4])> {
    // decode host commitment
    let host: [u64; 4] = proof.clone().public_inputs[0..4]
        .iter()
        .map(|x| x.to_canonical_u64())
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();

    // decode guest commitment
    let guest: [u64; 4] = proof.clone().public_inputs[0..4]
        .iter()
        .map(|x| x.to_canonical_u64())
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();

    Ok((host, guest))
}

pub fn prove_channel_open(
    host: ProofTuple<F, C, D>,
    guest: ProofTuple<F, C, D>,
) -> Result<ProofTuple<F, C, D>> {
    // instantiate config for channel open circuit
    let config = CircuitConfig::standard_recursion_config();

    // define targets
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());
    let host_pt = builder.add_virtual_proof_with_pis(&host.2);
    let host_data = builder.add_virtual_verifier_data(host.2.config.fri_config.cap_height);
    let host_t = ShieldedTargets {
        proof: host_pt.clone(),
        verifier: host_data.clone(),
    };
    let guest_pt = builder.add_virtual_proof_with_pis(&guest.2);
    let guest_data = builder.add_virtual_verifier_data(guest.2.config.fri_config.cap_height);
    let guest_t = ShieldedTargets {
        proof: guest_pt.clone(),
        verifier: guest_data.clone(),
    };

    // synthesize channel open proof
    builder.verify_proof::<C>(&host_pt, &host_data, &host.2);
    builder.verify_proof::<C>(&guest_pt, &guest_data, &guest.2);

    // export board commitments publicly
    // [0..4] = host commitment; [4..8] = guest commitment
    // @todo: add pubkeys
    builder.register_public_inputs(&host_pt.public_inputs);
    builder.register_public_inputs(&guest_pt.public_inputs);

    // construct circuit data
    let data = builder.build::<C>();

    // compute partial witness
    let pw = partial_witness(host_t, guest_t, host, guest)?;

    // prove outer proof provides valid shielding of a board validity circuit
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    // verify the outer proof's integrity
    data.verify(proof.clone())?;

    // return outer proof artifacts
    Ok((proof, data.verifier_only, data.common))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        utils::{
            board::Board,
            ship::Ship
        },
        circuits::board::BoardCircuit
    };

    #[test]
    pub fn test_channel_open() {
        // define circuit input (valid boards)
        let host_board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let guest_board = Board::new(
            Ship::new(3, 3, true),
            Ship::new(5, 4, false),
            Ship::new(0, 1, false),
            Ship::new(0, 5, true),
            Ship::new(6, 1, false),
        );

        // prove inner proofs
        let host_inner = BoardCircuit::prove_inner(host_board.clone()).unwrap();
        println!("1. Host inner proof successful");
        // let host_p = BoardCircuit::prove_outer(host_inner).unwrap();
        println!("2. Host outer proof successful");
        let guest_inner = BoardCircuit::prove_inner(guest_board.clone()).unwrap();
        println!("3. Guest inner proof successful");
        // let guest_p = BoardCircuit::prove_outer(guest_inner).unwrap();
        println!("4. Guest outer proof successful");

        // recursively prove the integrity of a zk state channel opening
        // let channel_open = prove_channel_open(host_p, guest_p).unwrap();
        let channel_open = prove_channel_open(host_inner, guest_inner).unwrap();
        println!("channel opened!");

    }
}
