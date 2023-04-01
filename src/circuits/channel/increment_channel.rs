use {
    super::{
        super::{ProofTuple, ShieldedTargets, C, D, F},
        {GameState, GameTargets},
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

/**
 * Decode public inputs of a state increment proof
 * @notice - also the channel open proof
 *
 * @param proof - proof from previous state increment containing serialized public inputs to marshall into GameState object
 * @return - GameState object that formats the previous state logically
 */
pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<GameState> {
    // decode host board commitment
    let host = proof.public_inputs.clone()[0..4]
        .iter()
        .map(|x| x.to_canonical_u64())
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();

    // decode guest board commitment
    let guest = proof.public_inputs.clone()[4..8]
        .iter()
        .map(|x| x.to_canonical_u64())
        .collect::<Vec<u64>>()
        .try_into()
        .unwrap();

    // decode # of htis made on host's board
    let host_damage = proof.public_inputs.clone()[8].to_canonical_u64() as u8;

    // decode # of hits made on guest's board
    let guest_damage = proof.public_inputs.clone()[9].to_canonical_u64() as u8;

    // decode turn boolean specifying whether it is the host's turn or the guest's turn
    let turn = proof.public_inputs.clone()[10].to_canonical_u64() != 0;

    // decode the serialized shot coordinate
    let shot = proof.public_inputs.clone()[11].to_canonical_u64() as u8;

    // return the state marshalled into a logical option
    Ok(GameState {
        host,
        guest,
        host_damage,
        guest_damage,
        turn,
        shot,
    })
}

/**
 * Witness the current state of the game and the next proof to be made
 *
 * @param prev_state - state of game before incrmeemnting
 * @param game_state_t - targets for inputted previous state for state increment
 * @param next_shot - the shot that the following state increment must evaluate for hit/ miss
 * @param next_shot_t - the targets for the following shot
 * @return - partial witness containing the values for constructing a state increment proof based on previous state
 */
pub fn partial_witness(
    prev_state: ProofTuple<F, C, D>,
    game_state_t: GameTargets,
    next_shot: [u8; 2],
    next_shot_t: [Target; 2],
) -> Result<PartialWitness<F>> {
    // construct partial witness
    let mut pw = PartialWitness::new();

    // extract the state from the previous state increment proof
    let state = decode_public(prev_state.0)?;

    // witness previous state proof (either channel open proof or channel state increment proof)
    pw.set_proof_with_pis_target(&game_state_t.prev_proof.proof, &prev_state.0);
    pw.set_verifier_data_target(&game_state_t.prev_proof.verifier, &prev_state.1);

    // witness host board commitment
    pw.set_target(game_state_t.host[0], F::from_canonical_u64(state.host[0]));
    pw.set_target(game_state_t.host[1], F::from_canonical_u64(state.host[1]));
    pw.set_target(game_state_t.host[2], F::from_canonical_u64(state.host[2]));
    pw.set_target(game_state_t.host[3], F::from_canonical_u64(state.host[3]));

    // witness guest board commitment
    pw.set_target(game_state_t.guest[0], F::from_canonical_u64(state.guest[0]));
    pw.set_target(game_state_t.guest[1], F::from_canonical_u64(state.guest[1]));
    pw.set_target(game_state_t.guest[2], F::from_canonical_u64(state.guest[2]));
    pw.set_target(game_state_t.guest[3], F::from_canonical_u64(state.guest[3]));

    // witness host damage
    pw.set_target(game_state_t.host_damage, F::from_canonical_u8(state.host_damage));

    // witness guest damage
    pw.set_target(game_state_t.guest_damage, F::from_canonical_u8(state.guest_damage));
    
    // witness turn
    pw.set_bool_target(game_state_t.turn, state.turn);

    // witness shot
    pw.set_target(game_state_t.shot, F::from_canonical_u8(state.shot));

    // return witnessed inputs
    Ok(pw)
}

/**
 * Given the current state of the game, increment the game by proving a hit/ miss and asserting a shot for next player
 * @dev todo: add ecc keypair to constrain host_turn order
 */
pub fn prove_channel_increment(state_t: GameTargets) -> Result<ProofWithPublicInputs<F, C, D>> {}

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
pub fn parstial_witness(
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

// pub fn

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
