use super::{C, D, F};
use crate::gadgets::{
    board::{decompose_board, recompose_board},
    range::less_than_10,
};
use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{BoolTarget, Target},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, CircuitData, VerifierCircuitTarget},
        config::{GenericConfig, PoseidonGoldilocksConfig},
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
        // targets //
        let ship: [ShipTarget; 5] = {
            (0..5).map(|_| {
                    let x = builder.add_virtual_target();
                    let y = builder.add_virtual_target();
                    let z = builder.add_virtual_bool_target_safe();
                    (x, y, z)
                })
                .collect::<Vec<ShipTarget>>()
                .try_into()
                .unwrap()
        };
        let board = builder.add_virtual_target_arr::<2>();

        // GADGETS //
        // comutation synthesis
        const L: usize = 5; // ship size of 5
        let board_in = decompose_board(board, &mut builder).unwrap();
        let board_out = place_ship::<L>(ship, board_in, &mut builder).unwrap();
        builder.register_public_inputs(&board_out);

        // proof inputs
        let mut pw = PartialWitness::new();
        /// board inputs (= 0 for now)
        pw.set_target(board[0], F::ZERO);
        pw.set_target(board[1], F::ZERO);
        /// ship inputs
        pw.set_target(ship.0, F::from_noncanonical_u128(3));
        pw.set_target(ship.1, F::from_canonical_u64(3));
        pw.set_bool_target(ship.2, true);

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        // verify board placement
        let res = data.verify(proof.clone());
        for i in 0..L {
            let coordinate = proof.public_inputs[i].to_canonical();
            println!("coordinate {}: {:?}", i, coordinate);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::{board::Board, ship::Ship};
    use plonky2::field::types::PrimeField64;

    // #[test]
    // fn test_compute_ship_placement_target_indexes() {
    //     let ship = [Target::new(0), Target::new(1), Target::new(2)];
    //     let targets = compute_ship_placement_target_indexes::<3>(ship);
    //     println!("targets = {:?}", targets);
    // }

    #[test]
    fn test_decompose_board() {
        // config
        let config = CircuitConfig::standard_recursion_config();

        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let board_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

        // decompose into bits
        let bits = decompose_board(board_t, &mut builder).unwrap();

        // proof inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let board_witness = board.canonical();
        println!("lmao");
        Board::print_canonical(&board_witness);
        println!("ayy");

        // proof witness
        let mut pw = PartialWitness::new();
        pw.set_target(board_t[0], F::from_canonical_u64(board_witness[0]));
        pw.set_target(board_t[1], F::from_canonical_u64(board_witness[1]));

        //@dev
        builder.register_public_inputs(&board_t);

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        // verify board placement
        let res = data.verify(proof.clone());
        let board_out = [
            proof.clone().public_inputs[0].to_canonical(),
            proof.clone().public_inputs[1].to_canonical(),
        ];
        println!("board[0] = {:?}", board_out[0]);
        println!("board[1] = {:?}", board_out[1]);
    }

    #[test]
    fn test_ship_to_coordinates() {
        // config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let ship: (Target, Target, BoolTarget) = {
            let x = builder.add_virtual_target();
            let y = builder.add_virtual_target();
            let z = builder.add_virtual_bool_target_safe();
            (x, y, z)
        };
        const L: usize = 5; // ship size of 5
        let coordinates: [Target; L] = ship_to_coordinates::<L>(ship, &mut builder).unwrap();
        builder.register_public_inputs(&coordinates);

        // proof inputs
        let mut pw = PartialWitness::new();
        pw.set_target(ship.0, F::from_canonical_u64(0));
        pw.set_target(ship.1, F::from_canonical_u64(0));
        pw.set_bool_target(ship.2, true);

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();
        println!("coordinates: {:?}", coordinates);

        // verify board placement
        let _ = data.verify(proof.clone());
        for i in 0..L {
            let coordinate = proof.public_inputs[i].to_canonical();
            println!("coordinate {}: {:?}", i, coordinate);
        }
    }

    #[test]
    pub fn test_place_ship() {}
}
