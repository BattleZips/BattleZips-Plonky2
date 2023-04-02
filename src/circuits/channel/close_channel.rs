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
            builder.select(turn_t, host_commitment_t[i], guest_commitment_t[i]);
        let loser_commit_limb = builder.select(turn_t, guest_commitment_t[i], host_commitment_t[i]);
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
    let proof = prove(
        &data.prover_only,
        &data.common,
        pw,
        &mut timing,
    )?;
    timing.print();

    // verify the proof was generated correctly
    data.verify(proof.clone())?;

    // PROVE //
    Ok((proof, data.verifier_only, data.common))
}
