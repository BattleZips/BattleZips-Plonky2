use super::{C, D, F};
use log::Level;

use crate::{
    gadgets::{
        board::{decompose_board, hash_board, place_ship, recompose_board},
        shot::{check_hit, serialize_shot},
    },
    utils::board::Board,
};
use anyhow::Result;
use plonky2::util::timing::TimingTree;
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, CommonCircuitData, VerifierOnlyCircuitData},
        proof::{Proof, ProofWithPublicInputs},
        prover::prove,
    },
};

// use ensure to check constraints
// pub fn place_ship() -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let mut builder = CircuitBuilder::<F, D>::new(config);

//     let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
//     Ok(())
// }

type ProofTuple<F, C, const D: usize> = (
    ProofWithPublicInputs<F, C, D>,
    VerifierOnlyCircuitData<C, D>,
    CommonCircuitData<F, D>,
);

pub struct BoardCircuitOutputs {
    commitment: [u64; 4],
}

pub type ShipTarget = (Target, Target, BoolTarget);

pub struct BoardCircuit {
    data: CircuitData<F, C, D>,
    ships: [ShipTarget; 5],
}

impl BoardCircuit {
    /**
     * Inner unshielded proof of board validity
     *
     * @param board - ships to place on the board
     * @param config - circuit configuration
     * @return - proof & circuit data
     */
    pub fn inner(board: Board, config: &CircuitConfig) -> Result<ProofTuple<F, C, D>> {
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        // TARGETS //
        // ship //
        let ships_t: [ShipTarget; 5] = {
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

        // generate
        // board (init) //
        // let board_serialized = builder.constants(&[F::from_canonical_u64(0); 2]);
        // let board_initial = builder.
        let board_blank: [Target; 4] = builder
            .constants(&[F::from_canonical_u32(0); 4])
            .try_into()
            .unwrap();
        let board_initial = decompose_board(board_blank, &mut builder).unwrap();
        // place ships on board
        let board_0 = place_ship::<5>(ships_t[0], board_initial, &mut builder).unwrap();
        let board_1 = place_ship::<4>(ships_t[1], board_0, &mut builder).unwrap();
        let board_2 = place_ship::<3>(ships_t[2], board_1, &mut builder).unwrap();
        let board_3 = place_ship::<3>(ships_t[3], board_2, &mut builder).unwrap();
        let board_5 = place_ship::<2>(ships_t[4], board_3, &mut builder).unwrap();

        // recompose board into u128
        let board_final = recompose_board(board_5.clone(), &mut builder).unwrap();

        // // hash the board into the commitment
        let commitment = hash_board(board_final, &mut builder).unwrap();

        // register public inputs (board commitment)
        builder.register_public_inputs(&commitment.elements);

        // export circuit data
        let data = builder.build::<C>();

        // PROVE EXECUTION //
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
            pw.set_target(ships_t[i].0, F::from_canonical_u8(ships[i].0));
            pw.set_target(ships_t[i].1, F::from_canonical_u8(ships[i].1));
            pw.set_bool_target(ships_t[i].2, ships[i].2);
        }
        let mut timing = TimingTree::new("prove", Level::Debug);

        let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
        timing.print();

        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }

    /**
     * Recursively wrap computation in zero knowledge
     */
    pub fn outer(
        inner: &ProofTuple<F, C, D>,
        config: &CircuitConfig,
    ) -> Result<ProofTuple<F, C, D>> {
        let (inner_proof, inner_vd, inner_cd) = inner;
        let mut builder = CircuitBuilder::<F, D>::new(config.clone());
        let pt = builder.add_virtual_proof_with_pis(inner_cd);

        let inner_data = builder.add_virtual_verifier_data(inner_cd.config.fri_config.cap_height);

        builder.verify_proof::<C>(&pt, &inner_data, inner_cd);

        builder.register_public_inputs(&pt.public_inputs);

        let data = builder.build::<C>();

        let mut pw = PartialWitness::new();
        pw.set_proof_with_pis_target(&pt, inner_proof);
        pw.set_verifier_data_target(&inner_data, inner_vd);

        let mut timing = TimingTree::new("prove", Level::Debug);
        let proof = prove(&data.prover_only, &data.common, pw, &mut timing)?;
        timing.print();

        data.verify(proof.clone())?;

        Ok((proof, data.verifier_only, data.common))
    }

    /**
     * Build the circuit for proving that a public board commitment is the poseidon hash of a valid board configuration
     *
     * @return - object storing circuit data and input targets
     */
    pub fn new() -> Result<BoardCircuit> {
        // CONFIG //
        let mut config = CircuitConfig::standard_recursion_config();
        // set wires for random access gate
        config.num_wires = 137;
        config.num_routed_wires = 130;
        config.zero_knowledge = true;

        // SYNTHESIS//
        // define circuit builder
        let mut builder = CircuitBuilder::<F, D>::new(config);
        // TARGETS //
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

        // generate
        // board (init) //
        // let board_serialized = builder.constants(&[F::from_canonical_u64(0); 2]);
        // let board_initial = builder.
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
        Ok(Self { data, ships })
    }

    pub fn prove(&self, board: Board) -> Result<ProofWithPublicInputs<F, C, D>> {
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
            pw.set_target(self.ships[i].0, F::from_canonical_u8(ships[i].0));
            pw.set_target(self.ships[i].1, F::from_canonical_u8(ships[i].1));
            pw.set_bool_target(self.ships[i].2, ships[i].2);
        }

        // PROVE //
        let proof = self.data.prove(pw).unwrap();
        Ok(proof)
    }

    pub fn verify(&self, proof: ProofWithPublicInputs<F, C, D>) -> Result<()> {
        self.data.verify(proof.clone())
    }

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

// pub struct ShieldedBoardCircuit {
//     data: CircuitData<F, C, D>,
//     ships: [ShipTarget; 5],
// }

// impl ShieldedBoardCircuit {
//     pub fn prove(board: Board) -> Result<ProofTuple<F, C, D>> {
//         // prove inner proof
//         let computation = BoardCircuit::new()?;
//         let proof = computation.prove(board.clone())?;

//         // CONFIG //
//         let mut config = CircuitConfig::standard_recursion_config();
//         config.zero_knowledge = true;

//         // SYNTHESIS //
//         // define circuit builder
//         let mut builder = CircuitBuilder::<F, D>::new(config);

//         // verify inner proof
//         builder.verify_proof
//         // TARGETS //
//         // let commitment = builder.add_virtual_target_arr::<4>();
//         // let proof = builder.add_virtual_proof_with_pis(common_data)
//         let proof = builder.add_virtual_proof_with_pis(common_data)
//     }
// }

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{board::Board, ship::Ship};

    #[test]
    fn test_valid_board() {
        // define inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );

        // build circuit
        let circuit = BoardCircuit::new().unwrap();

        // compute proof
        let proof = circuit.prove(board.clone()).unwrap();

        // verify proof
        assert_eq!((), circuit.verify(proof.clone()).unwrap());

        // verify integrity of public exports
        let output = BoardCircuit::decode_public(proof.clone()).unwrap();
        let expected_commitment = board.hash();
        // println!("output: {:?}", output.commitment);
        assert_eq!(output.commitment, expected_commitment);
    }

    #[test]
    fn test_shielded() {
        // CONFIG //
        let mut config_inner = CircuitConfig::standard_recursion_config();
        // set wires for random access gate
        config_inner.num_wires = 137;
        config_inner.num_routed_wires = 130;
        // config.zero_knowledge = true;

        // INNER //
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let inner = BoardCircuit::inner(board.clone(), &config_inner).unwrap();

        println!("Inner proven!");
        // OUTER //
        let mut config_outer = CircuitConfig::standard_recursion_config();
        // set wires for random access gate
        // config.num_wires = 137;
        // config.num_routed_wires = 130;
        config_outer.zero_knowledge = true;
        let outer = BoardCircuit::outer(&inner, &config_outer).unwrap();

        println!("Outer proven!");
        let commitment: [u64; 4] = outer
            .0
            .public_inputs
            .clone()
            .iter()
            .map(|x| x.to_canonical_u64())
            .collect::<Vec<u64>>()
            .try_into()
            .unwrap();

        let expected_commitment = board.hash();
        println!("output: {:?}", commitment);
        assert_eq!(commitment, expected_commitment);
    }
}
