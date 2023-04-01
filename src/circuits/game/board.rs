use {
    super::super::{ProofTuple, RecursiveTargets, C, D, F},
    crate::{
        gadgets::board::{decompose_board, hash_board, place_ship, recompose_board},
        utils::board::Board,
    },
    plonky2::{
        util::timing::TimingTree,
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
    },
    anyhow::Result,
    log::Level,
};

pub struct BoardCircuitOutputs {
    commitment: [u64; 4],
}

pub type ShipTarget = (Target, Target, BoolTarget);

pub struct BoardCircuit {
    data: CircuitData<F, C, D>,
    ships: [ShipTarget; 5],
}


// Argument of knowledge proving board commitment is the hash of a valid board config
// @dev inner proof that is recursively verified by outer proof to apply shielding
impl BoardCircuit {
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
     * Generate the witness for the board circuit inner proof inputs
     *
     * @param board - ship positions that dictate placement on board
     * @return - ship positions witnessed for inner proof synthesis
     */
    pub fn partial_witness_inner(
        targets: [ShipTarget; 5],
        board: Board,
    ) -> Result<PartialWitness<F>> {
        // build ship witness
        let ships: [(u8, u8, bool); 5] = [
            board.carrier.canonical(),
            board.battleship.canonical(),
            board.cruiser.canonical(),
            board.submarine.canonical(),
            board.destroyer.canonical(),
        ];

        // witness ships
        let mut pw = PartialWitness::new();
        for i in 0..ships.len() {
            pw.set_target(targets[i].0, F::from_canonical_u8(ships[i].0));
            pw.set_target(targets[i].1, F::from_canonical_u8(ships[i].1));
            pw.set_bool_target(targets[i].2, ships[i].2);
        }

        // return partial witness
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
     * Layout the circuit for proving that a public board commitment is the poseidon hash of a valid board configuration
     * 
     * @param config - circuit config
     * @return - circuit data and ship targets
     */
    pub fn build(config: &CircuitConfig) -> Result<BoardCircuit> {
        // define circuit builder
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());

        // ship //
        let ships: [ShipTarget; 5] = {
            (0..5)
                .map(|_| {
                    let x = builder.add_virtual_target();
                    let y = builder.add_virtual_target();
                    let z = builder.add_virtual_bool_target_safe();
                    (x, y, z)
                })
                .collect::<Vec<ShipTarget>>()
                .try_into()
                .unwrap()
        };

        // board (init) //
        let board_blank: [Target; 4] = builder
            .constants(&[F::from_canonical_u32(0); 4])
            .try_into()
            .unwrap();
        let board_initial = decompose_board(board_blank, &mut builder).unwrap();

        // place ships on board
        let board_0 = place_ship::<5>(ships[0], board_initial, &mut builder).unwrap();
        let board_1 = place_ship::<4>(ships[1], board_0, &mut builder).unwrap();
        let board_2 = place_ship::<3>(ships[2], board_1, &mut builder).unwrap();
        let board_3 = place_ship::<3>(ships[3], board_2, &mut builder).unwrap();
        let board_5 = place_ship::<2>(ships[4], board_3, &mut builder).unwrap();

        // recompose board into u128
        let board_final = recompose_board(board_5.clone(), &mut builder).unwrap();

        // // hash the board into the commitment
        let commitment = hash_board(board_final, &mut builder).unwrap();

        // register public inputs (board commitment)
        builder.register_public_inputs(&commitment.elements);

        // export circuit data
        let data = builder.build::<C>();

        // return circuit data and ship targets
        Ok(Self { data, ships })
    }

    /**
     * Given a board configuration, generate a proof that the board commitment is the poseidon hash of the board configuration
     *
     * @param board - board configuration
     * @return - proof tuple of everything needed to verify the proof natively or recursively
     */
    pub fn prove_inner(board: Board) -> Result<ProofTuple<F, C, D>> {
        // generate circuit config
        let config = BoardCircuit::config_inner()?;

        // build inner proof circuit
        let circuit = BoardCircuit::build(&config)?;

        // witness ships
        let pw = BoardCircuit::partial_witness_inner(circuit.ships, board)?;

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
        let config = BoardCircuit::config_outer()?;

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
        let pw = BoardCircuit::partial_witness_outer(inner, outer_targets)?;

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
     * Given a board validity proof, extract the public output of the board commitment
     *
     * @param proof - proof of proper execution of a board validity circuit
     * @return - 256-bit board commitment as a LE-serialized u64 array
     */
    pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<BoardCircuitOutputs> {
        let commitment: [u64; 4] = proof
            .clone()
            .public_inputs
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();
        Ok(BoardCircuitOutputs { commitment })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{board::Board, ship::Ship};

    #[test]
    fn test_shielded() {
        // define circuit input (valid board)
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );

        // prove inner proof
        let inner = BoardCircuit::prove_inner(board.clone()).unwrap();
        println!("Inner proof successful");

        // prove outer proof
        let outer = BoardCircuit::prove_outer(inner).unwrap();
        println!("Outer proof successful");

        // verify integrity of public board commitment
        let commitment = BoardCircuit::decode_public(outer.0).unwrap().commitment;
        let expected_commitment = board.hash();
        assert_eq!(commitment, expected_commitment);
    }
}
