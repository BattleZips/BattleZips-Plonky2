use {
    super::{
        super::{ProofTuple, ShieldedTargets, C, D, F},
        GameTargets
    },
    crate::gadgets::shot::serialize_shot,
    anyhow::Result,
    log::Level,
    plonky2::{
        field::types::{Field, PrimeField64},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder, circuit_data::CircuitConfig,
            proof::ProofWithPublicInputs, prover::prove,
        },
        util::timing::TimingTree,
    },
};

// BattleZips Channel Increment: Recursive (non zk) proof applying hit to game state

pub struct GameTargets {
    // @dev underconstrained without ecc keypairs
    pub host: [Target; 4], // host commitment
    pub guest: [Target; 4], // guest commitment
    pub host_damage: Target, // track hits on host board
    pub guest_damage: Target, // track hits on gues board
    pub host_turn: BoolTarget, // define the turn order
    pub shot: [Target; 2], // current shot coordinates
}

/**
 * Given the current state of the game, increment the game by proving a hit/ miss and asserting a shot for next player
 * @dev todo: add ecc keypair to constrain host_turn order
 */
pub fn prove_channel_increment(state_t: GameTargets) -> Result<ProofWithPublicInputs<F, C, D>> {
    
}

/**
 * Construct a partial witness for the channel open circuit
 *
 * @param host_t - targets for host proof
 * @param guest_t - targets for guest proof
 * @param host_p - host proof of valid board
 * @param guest_p - guest proof of valid board
 * @param shot - opening shot to be made by host
 * @param shot_t - targets for opening shot
 * @return partial witness for battleship channel open circuit
 */
pub fn partial_witness(
    host_p: ProofTuple<F, C, D>,
    guest_p: ProofTuple<F, C, D>,
    shot: [u8; 2],
    shot_t: [Target; 2],
) -> Result<PartialWitness<F>> {
    // construct partial witness
    let mut pw = PartialWitness::new();

    // witness host proof
    pw.set_proof_with_pis_target(&host_t.proof, &host_p.0);
    pw.set_verifier_data_target(&host_t.verifier, &host_p.1);

    // witness guest proof
    pw.set_proof_with_pis_target(&guest_t.proof, &guest_p.0);
    pw.set_verifier_data_target(&guest_t.verifier, &guest_p.1);

    // witness opening shot coordinates
    pw.set_target(shot_t[0], F::from_canonical_u8(shot[0]));
    pw.set_target(shot_t[1], F::from_canonical_u8(shot[1]));

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

/**
 * Construct a proof to open a Battleships game state channel
 *
 * @param host - proof of valid board made by host
 * @param guest - proof of valid board made by guest
 * @param shot - opening shot to be made by host
 * @return - proof that a valid game state channel has been opened
 */
pub fn prove_channel_open(
    host: ProofTuple<F, C, D>,
    guest: ProofTuple<F, C, D>,
    shot: [u8; 2],
) -> Result<ProofTuple<F, C, D>> {
    // instantiate config for channel open circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // TARGETS ///

    // host board proof targets
    let host_pt = builder.add_virtual_proof_with_pis(&host.2);
    let host_data = builder.add_virtual_verifier_data(host.2.config.fri_config.cap_height);
    let host_t = ShieldedTargets {
        proof: host_pt.clone(),
        verifier: host_data.clone(),
    };

    // guest board proof targets
    let guest_pt = builder.add_virtual_proof_with_pis(&guest.2);
    let guest_data = builder.add_virtual_verifier_data(guest.2.config.fri_config.cap_height);
    let guest_t = ShieldedTargets {
        proof: guest_pt.clone(),
        verifier: guest_data.clone(),
    };

    // opening shot coordinate targets
    let shot_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

    // SYNTHESIZE //
    // verify commitments from each player
    builder.verify_proof::<C>(&host_pt, &host_data, &host.2);
    builder.verify_proof::<C>(&guest_pt, &guest_data, &guest.2);

    // constrain the opening shot from the host
    let serialized_t = serialize_shot(shot_t[0], shot_t[1], &mut builder).unwrap();

    // export board commitments publicly
    //  - [0..4] = host commitment
    //  - [4..8] = guest commitment
    //  - [8] = serialized opening shot coordinate
    // @todo: add pubkeys
    builder.register_public_inputs(&host_pt.public_inputs);
    builder.register_public_inputs(&guest_pt.public_inputs);
    builder.register_public_input(serialized_t);

    // construct circuit data
    let data = builder.build::<C>();

    // compute partial witness
    let pw = partial_witness(host_t, guest_t, host, guest, shot, shot_t)?;

    // prove outer proof provides valid shielding of a board validity circuit
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    // verify the outer proof's integrity
    data.verify(proof.clone())?;

    // return outer proof artifacts
    Ok((proof, data.verifier_only, data.common))
}

pub fn 

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::game::board::BoardCircuit,
        utils::{board::Board, ship::Ship},
    };

    #[test]
    pub fn test_shielded_channel_open() {
        // INPUTS
        // host board (inner)
        let host_board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        // guest board (inner)
        let guest_board = Board::new(
            Ship::new(3, 3, true),
            Ship::new(5, 4, false),
            Ship::new(0, 1, false),
            Ship::new(0, 5, true),
            Ship::new(6, 1, false),
        );
        // opening shot (outer/ main opening chanel proof)
        let shot = [3u8, 4];

        // prove inner proofs
        let host_inner = BoardCircuit::prove_inner(host_board.clone()).unwrap();
        println!("1. Host inner proof successful");
        let host_p = BoardCircuit::prove_outer(host_inner).unwrap();
        println!("2. Host outer proof successful");
        let guest_inner = BoardCircuit::prove_inner(guest_board.clone()).unwrap();
        println!("3. Guest inner proof successful");
        let guest_p = BoardCircuit::prove_outer(guest_inner).unwrap();
        println!("4. Guest outer proof successful");

        // recursively prove the integrity of a zk state channel opening
        let channel_open = prove_channel_open(host_p, guest_p, shot).unwrap();
        println!("channel opened!");
    }

    #[test]
    pub fn test_unshielded_channel_open() {
        // @notice: not used in production but facilitates quick testing

        // INPUTS
        // host board (inner)
        let host_board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        // guest board (inner)
        let guest_board = Board::new(
            Ship::new(3, 3, true),
            Ship::new(5, 4, false),
            Ship::new(0, 1, false),
            Ship::new(0, 5, true),
            Ship::new(6, 1, false),
        );
        // opening shot (outer/ main opening chanel proof)
        let shot = [3u8, 4];

        // prove inner proofs
        let host = BoardCircuit::prove_inner(host_board.clone()).unwrap();
        println!("1. Host board proof successful");
        let guest = BoardCircuit::prove_inner(guest_board.clone()).unwrap();
        println!("2. Guest board proof successful");

        // recursively prove the integrity of a zk state channel opening
        _ = prove_channel_open(host, guest, shot).unwrap();
        println!("channel opened!");
    }
}
