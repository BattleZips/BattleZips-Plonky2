use super::{C, D, F};
use crate::{
    gadgets::{
        board::{hash_board, place_ship, recompose_board},
        shot::{check_hit, serialize_shot},
    },
    utils::board::Board,
};
use anyhow::Result;
use plonky2::{
    field::types::{Field, PrimeField64},
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData},
        proof::ProofWithPublicInputs,
    },
};

// use ensure to check constraints
// pub fn place_ship() -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let mut builder = CircuitBuilder::<F, D>::new(config);

//     let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
//     Ok(())
// }

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
        // config.zero_knowledge = true;

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
        let board_initial = builder.constants(&[F::from_canonical_u64(0); 128]);
        // place ships on board
        let board_0 = place_ship::<5>(ships[0], board_initial.clone(), &mut builder).unwrap();
        let board_1 = place_ship::<4>(ships[1], board_0.clone(), &mut builder).unwrap();
        let board_2 = place_ship::<3>(ships[2], board_1, &mut builder).unwrap();
        let board_3 = place_ship::<3>(ships[3], board_2, &mut builder).unwrap();
        let board_final = place_ship::<2>(ships[4], board_3, &mut builder).unwrap();

        // recompose board into u128
        let board = recompose_board(board_final.clone(), &mut builder).unwrap();
        // println!("LMAO: {:?}", board);
        // hash the board into the commitment
        let commitment = hash_board(board, &mut builder).unwrap();

        // register public inputs (board commitment)
        builder.register_public_inputs(&commitment.elements);

        // @dev
        // builder.register_public_inputs(&board_0);
        builder.register_public_inputs(&board_initial);
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

    // pub fn decode_public(proof: ProofWithPublicInputs<F, C, D>) -> Result<BoardCircuitOutputs> {
    //     let commitment: [u64; 4] = proof.clone()
    //         .public_inputs
    //         .iter()
    //         .map(|x| x.to_canonical_u64())
    //         .collect::<Vec<u64>>()
    //         .try_into()
    //         .unwrap();
    //     Ok(BoardCircuitOutputs { commitment })
    // }
}

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
        println!("ugh");
        let proof = circuit.prove(board.clone()).unwrap();

        // verify integrity of
        println!("work?");
        assert_eq!((), circuit.verify(proof.clone()).unwrap());
        // println!("work!");

        // verify integrity of public exports
        // let output = BoardCircuit::decode_public(proof.clone()).unwrap();
        // let expected_commitment = board.hash();
        // println!("output: {:?}", output.commitment);
        // assert_eq!(output.commitment, expected_commitment);
    }

    // fn test_invalid_board() {

    // }
}
