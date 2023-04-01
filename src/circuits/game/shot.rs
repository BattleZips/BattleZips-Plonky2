use {
    super::super::{ProofTuple, RecursiveTargets, C, D, F},
    crate::{
        gadgets::{
            board::hash_board,
            shot::{check_hit, serialize_shot},
        },
        utils::board::Board,
    },
    anyhow::Result,
    log::Level,
    plonky2::{
        field::types::{Field, PrimeField64},
        iop::{
            target::Target,
            witness::{PartialWitness, WitnessWrite},
        },
        plonk::{
            circuit_builder::CircuitBuilder,
            circuit_data::{CircuitConfig, CircuitData},
            proof::ProofWithPublicInputs,
            prover::prove,
        },
        util::timing::TimingTree,
    },
};

pub struct ShotCircuitOutputs {
    pub shot: u8,
    pub hit: bool,
    pub commitment: [u64; 4],
}

pub struct ShotCircuit {
    pub data: CircuitData<F, C, D>,
    pub board_t: [Target; 4],
    pub shot_t: [Target; 2],
}

impl ShotCircuit {
    /**
     * Generate a circuit config capable of handling 128 bit random access gates
     *
     * @return - circuit config
     */
    pub fn config_inner() -> Result<CircuitConfig> {
        let mut config = CircuitConfig::standard_recursion_config();
        // set wires for random access gate
        config.num_wires = 137;
        config.num_routed_wires = 130;
        Ok(config)
    }

    /**
     * Generate a circuit config that uses zero knowledge blinding
     *
     * @return - circuit config
     */
    pub fn config_outer() -> Result<CircuitConfig> {
        let mut config = CircuitConfig::standard_recursion_config();
        // toggle zero knowledge blinding
        config.zero_knowledge = true;
        Ok(config)
    }

    /**
     * Generate the witness for the shot circuit inner proof inputs
     *
     * @param shot - the shot coordinate (x, y)
     * @param board - the board configuration object
     * @param shot_t - the shot coordinate targets (x, y)
     * @param board_t - the board targets, a u128 serialized in LE by 4 u32s
     * @return - inner proof witness
     */
    pub fn partial_witness_inner(
        shot: [u8; 2],
        board: Board,
        shot_t: [Target; 2],
        board_t: [Target; 4],
    ) -> Result<PartialWitness<F>> {
        // marshall board into canonical form
        let board_canonical = board.canonical();

        // witness board state
        let mut pw = PartialWitness::new();
        pw.set_target(board_t[0], F::from_canonical_u32(board_canonical[0]));
        pw.set_target(board_t[1], F::from_canonical_u32(board_canonical[1]));
        pw.set_target(board_t[2], F::from_canonical_u32(board_canonical[2]));
        pw.set_target(board_t[3], F::from_canonical_u32(board_canonical[3]));

        // witness shot coordinate
        pw.set_target(shot_t[0], F::from_canonical_u8(shot[0]));
        pw.set_target(shot_t[1], F::from_canonical_u8(shot[1]));

        // return witnessed input variables
        Ok(pw)
    }

    /**
     * Generate the witness for the board circuit outer proof inputs
     *
     * @param inner - the proof tuple from the execution of the inner BoardCircuit proof
     * @param targets - the targets for the outer proof
     * @return - inner proof witnessed for outer proof synthesis
     */
    pub fn partial_witness_outer(
        inner: ProofTuple<F, C, D>,
        targets: RecursiveTargets,
    ) -> Result<PartialWitness<F>> {
        // instantiate partial witness
        let mut pw = PartialWitness::new();

        // input inner proof to partial witness
        pw.set_proof_with_pis_target(&targets.proof, &inner.0);
        pw.set_verifier_data_target(&targets.verifier, &inner.1);

        // return recursive partial witness
        Ok(pw)
    }

    /**
     * Layout the circuit for proving that a given shot coordinate hits or misses on a committed board
     *
     * @param config - circuit config
     * @return - circuit data and board/ shot targets
     */
    pub fn build(config: &CircuitConfig) -> Result<ShotCircuit> {
        // define circuit builder
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // input targets
        let board_t: [Target; 4] = builder.add_virtual_targets(4).try_into().unwrap();
        let shot_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

        // serialize shot coordinate
        let serialized_t = serialize_shot(shot_t[0], shot_t[1], &mut builder).unwrap();

        // export serialized shot value
        builder.register_public_input(serialized_t);

        // check for hit or miss
        let hit = check_hit(board_t, serialized_t, &mut builder).unwrap();

        // export hit/ miss boolean
        builder.register_public_input(hit);

        // compute public hash of board
        let board_hash_t = hash_board(board_t, &mut builder).unwrap();

        // export binding commitment to board publicly
        // @dev todo: making commitment blinding as well (alternatively hide behind ecdsa signature)
        builder.register_public_inputs(&board_hash_t.elements);

        // return circuit data and input targets
        let data = builder.build::<C>();
        Ok(Self {
            data,
            board_t,
            shot_t,
        })
    }

    /**
     * Given a board configuration, generate a proof that the board commitment is the poseidon hash of the board configuration
     *
     * @param board - board configuration
     * @return - proof tuple of everything needed to verify the proof natively or recursively
     */
    pub fn prove_inner(board: Board, shot: [u8; 2]) -> Result<ProofTuple<F, C, D>> {
        // generate circuit config
        let config = ShotCircuit::config_inner()?;

        // build inner proof circuit
        let circuit = ShotCircuit::build(&config)?;

        // witness board and shot
        let pw = ShotCircuit::partial_witness_inner(shot, board, circuit.shot_t, circuit.board_t)?;

        // generate proof
        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(
            &circuit.data.prover_only,
            &circuit.data.common,
            pw,
            &mut timing,
        )?;
        timing.print();

        // verify the proof was generated correctly
        circuit.data.verify(proof.clone())?;

        // PROVE //
        Ok((proof, circuit.data.verifier_only, circuit.data.common))
    }

    /**
     * Recursive outer proof that obfuscates information of inner proof
     *
     * @param inner - the proof tuple from the execution of the inner BoardCircuit proof
     * @return - outer proof tuple of everything needed to verify the proof natively or recursively
     */
    pub fn prove_outer(inner: ProofTuple<F, C, D>) -> Result<ProofTuple<F, C, D>> {
        // generate circuit config
        let config = ShotCircuit::config_outer()?;

        // define targets
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let pt = builder.add_virtual_proof_with_pis(&inner.2);
        let inner_data = builder.add_virtual_verifier_data(inner.2.config.fri_config.cap_height);
        let outer_targets = RecursiveTargets {
            proof: pt.clone(),
            verifier: inner_data.clone(),
        };

        // synthesize outer proof
        builder.verify_proof::<C>(&pt, &inner_data, &inner.2);

        // pipe commitment to outer proof public inputs
        builder.register_public_inputs(&pt.public_inputs);

        // construct circuit data
        let data = builder.build::<C>();

        // compute partial witness
        let pw = ShotCircuit::partial_witness_outer(inner, outer_targets)?;

        // prove outer proof provides valid shielding of a board validity circuit
        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
        timing.print();

        // verify the outer proof's integrity
        data.verify(proof.clone())?;

        // return outer proof artifacts
        Ok((proof, data.verifier_only, data.common))
    }

    /**
     * Decode the output of a shot proof
     *
     * @param proof - proof from shot circuit
     * @return - formatted outputs from shot ciruit
     */
    pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<ShotCircuitOutputs> {
        let public_inputs = proof.clone().public_inputs;
        let shot = public_inputs[0].to_canonical_u64() as u8;
        let hit = public_inputs[1].to_canonical_u64() != 0;
        let commitment: [u64; 4] = public_inputs[2..6]
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();
        Ok(ShotCircuitOutputs {
            shot,
            hit,
            commitment,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::utils::{board::Board, ship::Ship};

    // Carrier: 3, 4, false
    // Battleship: 9, 6, true
    // Cruiser: 0, 0, false
    // Submarine: 0, 6, false
    // Destroyer: 6, 1, true
    // (Y)
    // 9 | 0 0 0 0 0 0 0 0 0 1
    // 8 | 0 0 0 0 0 0 0 0 0 1
    // 7 | 0 0 0 0 0 0 0 0 0 1
    // 6 | 1 1 1 0 0 0 0 0 0 1
    // 5 | 0 0 0 0 0 0 0 0 0 0
    // 4 | 0 0 0 1 1 1 1 1 0 0
    // 3 | 0 0 0 0 0 0 0 0 0 0
    // 2 | 0 0 0 0 0 0 1 0 0 0
    // 1 | 0 0 0 0 0 0 1 0 0 0
    // 0 | 1 1 1 0 0 0 0 0 0 0
    //    -------------------- (X)
    //     0 1 2 3 4 5 6 7 8 9

    #[test]
    fn test_shot_hit() {
        // define inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let shot = [0u8, 0];

        // prove inner proof
        let inner = ShotCircuit::prove_inner(board.clone(), shot.clone()).unwrap();
        println!("Inner proof successful");

        // prove outer proof
        let outer = ShotCircuit::prove_outer(inner).unwrap();
        println!("Outer proof successful");

        // verify integrity of public exports
        let output = ShotCircuit::decode_public(outer.0.clone()).unwrap();
        let expected_shot = 0u8;
        let expected_hit = true;
        let expected_commitment = board.hash();
        assert_eq!(output.shot, expected_shot);
        assert_eq!(output.hit, expected_hit);
        assert_eq!(output.commitment, expected_commitment);
    }

    #[test]
    fn test_shot_miss() {
        // define inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let shot = [0u8, 1];

        // prove inner proof
        let inner = ShotCircuit::prove_inner(board.clone(), shot.clone()).unwrap();
        println!("Inner proof successful");

        // prove outer proof
        let outer = ShotCircuit::prove_outer(inner).unwrap();
        println!("Outer proof successful");

        // verify integrity of public exports
        let output = ShotCircuit::decode_public(outer.0.clone()).unwrap();
        let expected_shot = 10u8;
        let expected_hit = false;
        let expected_commitment = board.hash();
        assert_eq!(output.shot, expected_shot);
        assert_eq!(output.hit, expected_hit);
        assert_eq!(output.commitment, expected_commitment);
    }
    // }
}
