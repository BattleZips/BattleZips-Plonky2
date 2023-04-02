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

/**
 * Witness the inputs to a channel close circuit
 *
 * @state_increment_p - proof of valid state increment (must be final increment in state channel)
 * @state_increment_pt - targets for state increment proof
 * @param host_commitment_t - targets for host board commitment
 * @param guest_commitment_t - targets for guest board commitment
 * @param host_damage - host damage target
 * @param guest_damage - guest damage target
 * @param turn - turn boolean target
 * @return - partial witness for channel close circuit summarizing a valid battleship game
 */
pub fn partial_witness(
    state_increment_p: ProofTuple<F, C, D>,
    state_increment_pt: RecursiveTargets,
    host_commitment_t: [Target; 4],
    guest_commitment_t: [Target; 4],
    host_damage_t: Target,
    guest_damage_t: Target,
    turn_t: BoolTarget,
) -> Result<PartialWitness<F>> {
    // construct partial witness
    let mut pw = PartialWitness::new();

    // witness final state increment proof
    pw.set_proof_with_pis_target(&state_increment_pt.proof, &state_increment_p.0.clone());
    pw.set_verifier_data_target(&state_increment_pt.verifier, &state_increment_p.1.clone());

    // witness host board commitment
    let host_commitment_p: [F; 4] = state_increment_p.0.clone().public_inputs[0..4]
        .try_into()
        .unwrap();
    pw.set_target(host_commitment_t[0], host_commitment_p[0]);
    pw.set_target(host_commitment_t[1], host_commitment_p[1]);
    pw.set_target(host_commitment_t[2], host_commitment_p[2]);
    pw.set_target(host_commitment_t[3], host_commitment_p[3]);

    // witness guest board commitment
    let guest_commitment_p: [F; 4] = state_increment_p.0.clone().public_inputs[4..8]
        .try_into()
        .unwrap();
    pw.set_target(guest_commitment_t[0], guest_commitment_p[0]);
    pw.set_target(guest_commitment_t[1], guest_commitment_p[1]);
    pw.set_target(guest_commitment_t[2], guest_commitment_p[2]);
    pw.set_target(guest_commitment_t[3], guest_commitment_p[3]);

    // witness host damage
    let host_damage = state_increment_p.0.clone().public_inputs[8];
    pw.set_target(host_damage_t, host_damage);

    // witness guest damage
    let guest_damage = state_increment_p.0.clone().public_inputs[9];
    pw.set_target(guest_damage_t, guest_damage);

    // witness turn voolean
    let turn = state_increment_p.0.clone().public_inputs[10].to_canonical_u64() != 0;
    pw.set_bool_target(turn_t, turn);

    // return partial witness
    Ok(pw)
}

/**
 * Finalize a ZK State Channel by proving the end condition (17 hits) is met
 */
pub fn prove_close_channel(state_p: ProofTuple<F, C, D>) -> Result<ProofTuple<F, C, D>> {
    // CONFIG //
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config.clone());

    // TARGETS //
    let state_increment_pt = RecursiveTargets {
        proof: builder.add_virtual_proof_with_pis(&state_p.2),
        verifier: builder.add_virtual_verifier_data(state_p.2.config.fri_config.cap_height),
    };
    let host_commitment_t = builder.add_virtual_target_arr::<4>();
    let guest_commitment_t = builder.add_virtual_target_arr::<4>();
    let host_damage_t = builder.add_virtual_target();
    let guest_damage_t = builder.add_virtual_target();
    let turn_t = builder.add_virtual_bool_target_safe();

    // SYNTHESIZE //
    // verify state increment proof
    builder.verify_proof::<C>(
        &state_increment_pt.proof,
        &state_increment_pt.verifier,
        &state_p.2,
    );
    // multiplex damage to evaluate whether end condition is met
    let threshold = builder.constant(F::from_canonical_u8(17));
    let damage_t = builder.select(turn_t, host_damage_t, guest_damage_t);
    let end_condition = builder.is_equal(damage_t, threshold);
    let end_const = builder.constant_bool(true);
    builder.connect(end_condition.target, end_const.target); // will fail if end condition is not met

    // multiplex winner and loser boards
    let winner_commit_t = builder.add_virtual_target_arr::<4>();
    let loser_commit_t = builder.add_virtual_target_arr::<4>();
    for i in 0..winner_commit_t.len() {
        let winner_commit_limb =
            builder.select(turn_t, guest_commitment_t[i], host_commitment_t[i]);
        let loser_commit_limb = builder.select(turn_t, host_commitment_t[i], guest_commitment_t[i]);
        builder.connect(winner_commit_t[i], winner_commit_limb);
        builder.connect(loser_commit_t[i], loser_commit_limb);
    }

    // PUBLIC INPUTS //
    // register winner as [0..4]
    builder.register_public_inputs(&winner_commit_t);
    // register loser as [4..8]
    builder.register_public_inputs(&loser_commit_t);

    // WITNESS //
    let pw = partial_witness(
        state_p.clone(),
        state_increment_pt,
        host_commitment_t,
        guest_commitment_t,
        host_damage_t,
        guest_damage_t,
        turn_t,
    )?;

    // PROVE //
    // construct circuit data
    let data = builder.build::<C>();
    // generate proof
    let mut timing = TimingTree::new("prove", Level::Debug);
    let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
    timing.print();

    // verify the proof was generated correctly
    data.verify(proof.clone())?;

    // PROVE //
    Ok((proof, data.verifier_only, data.common))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        circuits::{
            channel::{increment_channel::StateIncrementCircuit, open_channel::prove_channel_open},
            game::{board::BoardCircuit, shot::ShotCircuit},
        },
        utils::{board::Board, ship::Ship},
    };

    // series of shots that will hit every position on the host board configuration
    const HOST_HIT_COORDS: [[u8; 2]; 18] = [
        [0, 0],
        [1, 0],
        [2, 0],
        [6, 1],
        [6, 2],
        [3, 4],
        [4, 4],
        [5, 4],
        [6, 4],
        [7, 4],
        [0, 6],
        [1, 6],
        [2, 6],
        [9, 6],
        [9, 7],
        [9, 8],
        [9, 9],
        [8, 8] // dummy coordinate
    ];

    /**
     * Open a ZK State Channel by proving a valid board configuration for both host and guest
     *
     * @param host - the board configuration for the host
     * @param guest - the board configuration for the guest
     * @param shot - the first shot made by the host
     * @returns a proof tuple for the open channel circuit
     */
    pub fn open_channel(host: Board, guest: Board, shot: [u8; 2]) -> Result<ProofTuple<F, C, D>> {
        let host = BoardCircuit::prove_inner(host.clone()).unwrap();
        let guest = BoardCircuit::prove_inner(guest.clone()).unwrap();
        let open_proof = prove_channel_open(host, guest, shot).unwrap();
        println!("channel opened!");
        Ok(open_proof)
    }

    /**
     * Increment the state of a ZK State Channel by proving a shot was made
     *
     * @param board - the board configuration being checked
     * @param shot - the shot being checked against the board in this state increment
     * @param prev - the previous state of the channel
     * @param next_shot - the next shot to be checked in subsequent state increment
     * @return - a proof tuple for the state increment
     */
    pub fn increment_channel_state(
        board: Board,
        shot: [u8; 2],
        prev: ProofTuple<F, C, D>,
        next_shot: [u8; 2],
    ) -> Result<ProofTuple<F, C, D>> {
        let shot_proof = ShotCircuit::prove_inner(board.clone(), shot).unwrap();
        Ok(StateIncrementCircuit::prove(prev.clone(), shot_proof.clone(), next_shot).unwrap())
    }

    #[test]
    pub fn test_unshielded_zk_state_channel() {
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

        // CHANNEL OPEN PROOF
        let mut previous_p =
            open_channel(host_board.clone(), guest_board.clone(), HOST_HIT_COORDS[0]).unwrap();

        // recursively prove entire state channel
        for i in 0..HOST_HIT_COORDS.len() - 1 {

            // GUEST state increment
            previous_p = increment_channel_state(
                guest_board.clone(),
                HOST_HIT_COORDS[i],
                previous_p.clone(),
                HOST_HIT_COORDS[i],
            )
            .unwrap();
            println!("guest state increment #{}", i + 1);

            // HOST state increment
            previous_p = increment_channel_state(
                host_board.clone(),
                HOST_HIT_COORDS[i],
                previous_p.clone(),
                HOST_HIT_COORDS[i + 1],
            )
            .unwrap();
            println!("host state increment #{}", i + 1);
        }

        // FINALIZE STATE CHANNEL
        let state_channel_proof = prove_close_channel(previous_p.clone()).unwrap();

        // Check State Channel Increment Outputs
        let winner: [u64; 4] = state_channel_proof.0.clone().public_inputs[0..4]
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();
        let loser: [u64; 4] = state_channel_proof.0.clone().public_inputs[4..8]
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();
        let expected_winner = guest_board.hash();
        let expected_loser = host_board.hash();
        assert_eq!(winner, expected_winner);
        assert_eq!(loser, expected_loser);
    }
}
