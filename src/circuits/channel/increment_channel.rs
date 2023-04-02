use plonky2::iop::witness;

use {
    super::{
        super::{ProofTuple, RecursiveTargets, C, D, F},
        {GameState, GameTargets},
    },
    crate::{circuits::game::shot::ShotCircuit, gadgets::shot::serialize_shot},
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
            circuit_data::CircuitConfig,
            circuit_data::{CircuitData, CommonCircuitData},
            proof::ProofWithPublicInputs,
            prover::prove,
        },
        util::timing::TimingTree,
    },
};

// BattleZips Channel Increment: Recursive (non zk) proof applying hit to game state

// State Increment Circuit Object
pub struct StateIncrementCircuit {
    pub data: CircuitData<F, C, D>, // circuit data for a given state increment
    pub prev: GameTargets,          // targets for previous state increment proof
    pub shot: RecursiveTargets,     // targets for shot proof
    pub shot_t: [Target; 2],        // targets for shot coordinates
}

// Targets for recursive shot proof verification
pub struct ShotProofTargets {
    proof: RecursiveTargets,
    commitment: [Target; 4],
    hit: BoolTarget,
    shot: Target,
}

impl StateIncrementCircuit {
    /**
     * Witness the inner shot proof
     *
     * @param pw - partial witness to write to
     * @param shot_p - inner shot proof of state increment
     * @param shot_pt - targets of inner shot proof
     * @param commitment_t - targets of commitments to host and guest boards
     * @param hit_t - target of hit boolean
     * @param shot_t - target of serialized shot coordinate
     * @return - error or success
     */
    pub fn witness_shot(
        pw: &mut PartialWitness<F>,
        shot_p: ProofTuple<F, C, D>,
        shot_pt: RecursiveTargets,
        commitment_t: [Target; 4],
        hit_t: BoolTarget,
        shot_t: Target,
    ) -> Result<()> {
        // extract proof inputs from shot circuit
        let outputs = ShotCircuit::decode_public(shot_p.0.clone())?;

        // witness shot proof
        pw.set_proof_with_pis_target(&shot_pt.proof, &shot_p.0);
        pw.set_verifier_data_target(&shot_pt.verifier, &shot_p.1);

        // witness commitment of board checked in shot proof
        pw.set_target(
            commitment_t[0],
            F::from_canonical_u64(outputs.commitment[0]),
        );
        pw.set_target(
            commitment_t[1],
            F::from_canonical_u64(outputs.commitment[1]),
        );
        pw.set_target(
            commitment_t[2],
            F::from_canonical_u64(outputs.commitment[2]),
        );
        pw.set_target(
            commitment_t[3],
            F::from_canonical_u64(outputs.commitment[3]),
        );

        // witness hit/miss assertion
        pw.set_bool_target(hit_t, outputs.hit);

        // witness serialized shot coordinate
        pw.set_target(shot_t, F::from_canonical_u8(outputs.shot));

        // return success after mutating partial witness
        Ok(())
    }

    /**
     * Witness the previous state increment proof
     *
     * @param pw - partial witness to write to
     * @param prev_state - previous state increment proof tuple
     * @param game_state_t - targets of previous state increment proof
     *
     * @return - error or success
     */
    pub fn witness_prev_state(
        pw: &mut PartialWitness<F>,
        prev_state: ProofTuple<F, C, D>,
        game_state_t: GameTargets,
    ) -> Result<()> {
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
        pw.set_target(
            game_state_t.host_damage,
            F::from_canonical_u8(state.host_damage),
        );

        // witness guest damage
        pw.set_target(
            game_state_t.guest_damage,
            F::from_canonical_u8(state.guest_damage),
        );

        // witness turn
        pw.set_bool_target(game_state_t.turn, state.turn);

        // witness shot
        pw.set_target(game_state_t.shot, F::from_canonical_u8(state.shot));

        // return ok with witnessed inputs in mutated pw
        Ok(())
    }

    /**
     * Witness the x, y coordinates of the next shot (that the subsequent state increment must approve)
     * @notice if the state increment reaches an end condition, the next shot is ignored for channel closing
     *
     * @param pw - partial witness to write to
     * @param next_shot - shot x, y coordinates to check against next state increment
     * @param next_shot_t - targets of next shot coordinates
     * @return - error or success
     */
    pub fn witness_next_shot(
        pw: &mut PartialWitness<F>,
        next_shot: [u8; 2],
        next_shot_t: [Target; 2],
    ) -> Result<()> {
        // witness next shot coordinate
        pw.set_target(next_shot_t[0], F::from_canonical_u8(next_shot[0]));
        pw.set_target(next_shot_t[1], F::from_canonical_u8(next_shot[1]));

        // return ok with witnessed inputs in mutated pw
        Ok(())
    }

    /**
     * Construct virtual targets for the public inputs of a state increment proof in a logically formatted GameTargets object
     *
     * @param common - common circuit data used to verify a state increment circuit
     * @param builder - circuit builder to construct circuit with
     * @return - a GameTargets object that stores virtual targets according to logical purpose of a state increment
     */
    pub fn game_state_targets(
        common: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<GameTargets> {
        Ok(GameTargets {
            prev_proof: RecursiveTargets {
                proof: builder.add_virtual_proof_with_pis(common),
                verifier: builder.add_virtual_verifier_data(common.config.fri_config.cap_height),
            },
            host: builder.add_virtual_target_arr::<4>(),
            guest: builder.add_virtual_target_arr::<4>(),
            host_damage: builder.add_virtual_target(),
            guest_damage: builder.add_virtual_target(),
            turn: builder.add_virtual_bool_target_safe(),
            shot: builder.add_virtual_target(),
        })
    }

    /**
     * Construct virtual targets for the public inputs of a shot proof in a logically formatted ShotProofTargets object
     *
     * @param common - common circuit data used to verify a shot circuit
     * @param builder - circuit builder to construct circuit with
     * @return - a GameTargets object that stores virtual targets according to logical purpose of a state increment
     */
    pub fn shot_proof_targets(
        common: &CommonCircuitData<F, D>,
        builder: &mut CircuitBuilder<F, D>,
    ) -> Result<ShotProofTargets> {
        Ok(ShotProofTargets {
            proof: RecursiveTargets {
                proof: builder.add_virtual_proof_with_pis(common),
                verifier: builder.add_virtual_verifier_data(common.config.fri_config.cap_height),
            },
            commitment: builder.add_virtual_target_arr::<4>(),
            hit: builder.add_virtual_bool_target_safe(),
            shot: builder.add_virtual_target(),
        })
    }

    /**
     * Apply copy constraints to commitments between prev state increment proof and shot proof
     * @notice multiplexes targeted commitment based on turn boolean
     * @dev board commitment checked in shot proof must be equal to the private state committed to in channel open
     *
     * @param builder - circuit builder to construct circuit with
     * @param prev - previous state increment proof targets
     * @param shot - shot proof targets
     * @return - success if copy constraints on board commitment are satisfied, or error
     */
    pub fn constrain_commitment(
        builder: &mut CircuitBuilder<F, D>,
        prev: &GameTargets,
        shot: &ShotProofTargets,
    ) -> Result<()> {
        // define constained commitment targets
        let constrained_commitment = builder.add_virtual_target_arr::<4>();
        for i in 0..constrained_commitment.len() {
            // multiplex between host and guest commitment based on turn
            let limb = builder.select(prev.turn, prev.guest[i], prev.host[i]);
            // constrain commitment target based on multiplexed input
            builder.connect(constrained_commitment[i], limb);
        }
        // return as a success
        Ok(())
    }

    /**
     * Apply copy constraints to shot coordinates between prev state increment proof and shot proof
     * @dev shot coordinate checked in shot proof must be equal to the "next shot" made in the previous state increment proof
     *
     * @param builder - circuit builder to construct circuit with
     * @param prev - previous state increment proof targets
     * @param shot - shot proof targets
     * @return - success if copy constraints on board commitment are satisfied, or error
     */
    pub fn constrain_shot(
        builder: &mut CircuitBuilder<F, D>,
        prev: &GameTargets,
        shot: &ShotProofTargets,
    ) -> Result<()> {
        // constrain shot coordinate
        builder.connect(prev.shot, shot.shot);
        // return as a success
        Ok(())
    }

    /**
     * Prove the validity of a sequential state increment
     *
     * @param prev - previous state increment proof
     * @param shot - shot proof that informs the state increment
     * @param next - next shot to be evaluated in subsequent state increment
     * @return - a channel state increment circuit
     */
    pub fn prove(
        prev: ProofTuple<F, C, D>,
        shot: ProofTuple<F, C, D>,
        next: [u8; 2],
    ) -> Result<StateIncrementCircuit> {
        // CONFIG //
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // TARGETS //
        // prev state increment proof targets
        let prev_state_t = StateIncrementCircuit::game_state_targets(&prev.2, &mut builder)?;
        // shot proof targets
        let shot_t = StateIncrementCircuit::shot_proof_targets(&shot.2, &mut builder)?;
        // next shot targets
        let next_shot_t = builder.add_virtual_target_arr::<2>();

        // SYNTHESIZE //
        // verify inner proofs
        builder.verify_proof::<C>(
            &prev_state_t.prev_proof.proof,
            &prev_state_t.prev_proof.verifier,
            &prev.2,
        );
        builder.verify_proof::<C>(&shot_t.proof.proof, &shot_t.proof.verifier, &shot.2);
        // copy constrain values checked in shot proof against values to be checked according to previous state increment
        StateIncrementCircuit::constrain_commitment(&mut builder, &&prev_state_t, &shot_t)?;
        StateIncrementCircuit::constrain_shot(&mut builder, &&prev_state_t, &shot_t)?;
        // serialize next shot to be verified in subsequent state increment proof
        let next_shot_serialized_t = serialize_shot(next_shot_t[0], next_shot_t[1], &mut builder)?;
        // flip turn (0 = 0 -> 1; 1 = 0 -> 0)
        let zero = builder.constant(F::ZERO);
        let next_turn_t = builder.is_equal(targets.turn.target, zero);

        // PUBLIC INPUTS //
    }
}

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
 * Given the current state of the game, increment the game by proving a hit/ miss and asserting a shot for next player
 * @dev todo: add ecc keypair to constrain host_turn order
 */
pub fn prove_channel_increment(
    prev_p: ProofTuple<F, C, D>,
    shot_p: ProofTuple<F, C, D>,
    shot: [u8; 2],
) -> Result<ProofTuple<F, C, D>> {
    // instantiate config for channel open circuit
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // TARGETS //

    // channel targets
    // let targets = ;

    // inner shot proof targets
    let shot_pt = RecursiveTargets {
        proof: builder.add_virtual_proof_with_pis(&shot_p.2),
        verifier: builder.add_virtual_verifier_data(shot_p.2.config.fri_config.cap_height),
    };

    // shot proof output targets
    let commitment_t = builder.add_virtual_target_arr::<4>();
    let hit_t = builder.add_virtual_bool_target_safe();
    let shot_t = builder.add_virtual_target();

    // next shot targets
    let next_shot_t = builder.add_virtual_target_arr::<2>();

    // SYNTHESIZE //
    // verify inner proofs
    builder.verify_proof::<C>(
        &targets.prev_proof.proof,
        &targets.prev_proof.verifier,
        &prev_p.2,
    );
    builder.verify_proof::<C>(&shot_pt.proof, &shot_pt.verifier, &shot_p.2);

    // mutiplex damage equation
    // if turn = 1, ignore increment as hits apply to guest, else increment according to hit value
    let host_damage_increment = builder.add(targets.host_damage, hit_t.target);
    let multiplexed_host_damage =
        builder.select(targets.turn, targets.host_damage, host_damage_increment);

    // if turn = 0, ignore increment as hits apply to host, else increment according to hit value
    let guest_damage_increment = builder.add(targets.host_damage, hit_t.target);
    let multiplexed_guest_damage =
        builder.select(targets.turn, guest_damage_increment, targets.guest_damage);

    // serialize next shot
    let serialized_t = serialize_shot(next_shot_t[0], next_shot_t[1], &mut builder).unwrap();

    // flip turn
    let zero = builder.constant(F::ZERO);
    // 0 = 0 -> 1; 1 = 0 -> 0
    let next_turn_t = builder.is_equal(targets.turn.target, zero);

    // OUTPUTS //
    // pipe through the board commitments
    builder.register_public_inputs(&targets.host);
    builder.register_public_inputs(&targets.guest);

    // output mutiplexed damage values
    builder.register_public_input(multiplexed_host_damage);
    builder.register_public_input(multiplexed_guest_damage);

    // output flipped turn
    builder.register_public_input(targets.turn.target);

    // output the shot that the next state increment must verify
    builder.register_public_input(serialized_t);

    // WITNESS //
    let mut pw = PartialWitness::new();
    // witness shot proof
    witness_shot(&mut pw, shot_p, shot_pt, commitment_t, hit_t, shot_t);

    // witness previous state proof
    witness_prev_state(&mut pw, prev_p, targets);

    // witness next shot
    witness_next_shot(&mut pw, shot, next_shot_t);
    // PROVE //
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
