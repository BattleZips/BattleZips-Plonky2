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
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};
use super::{D, C, F};
use crate::gadgets::{
    range::less_than_10,
    board::{decompose_board, recompose_board}
};


/**
 * Given a ship head coordinate, orientation, and offset, compute the occupied coordinate + a boolean of whether offset coordinate is in range
 * @dev copy constraint will fail if x/ y coordinate is not in range
 *
 * @param x - x coordinate of ship head
 * @param y - y coordinate of ship head
 * @param z - orientation of ship head
 * @param offset - offset from ship head
 * @param builder - circuit builder
 * @return - coordinate of ship placement
 */
pub fn generate_coordiante(
    x: Target,
    y: Target,
    z: BoolTarget,
    offset: usize,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<(Target)> {
    // define constants: offset length & y serialization (mul by 10)
    let offset_t = builder.constant(F::from_canonical_u8(offset as u8));
    let ten_t = builder.constant(F::from_canonical_u8(10));
    // add offsets to x
    let x_offset_t = builder.add(x, offset_t);
    let y_offset_t = builder.add(y, offset_t);
    // check range for offset coordinate plane cooresponding to orinentiation
    let range_check_t = builder.select(z, y_offset_t, x_offset_t);
    less_than_10(range_check_t, builder)?;
    // multiplex values for final coordiante expression
    let x_t = builder.select(z, x, x_offset_t);
    let y_t = builder.select(z, y_offset_t, y);
    // compute coordinate value
    let y_serialized_t = builder.mul(y_t, ten_t);
    Ok(builder.add(x_t, y_serialized_t))
}

/**
 * Given a ship as (x, y, z) with a constant ship length, compute the occupied coordinates
 *
 * @param ship - ship instantiation coordinates
 * @param builder - circuit builder
 */
pub fn ship_to_coordinates<const L: usize>(
    ship: (Target, Target, BoolTarget),
    builder: &mut CircuitBuilder<F, D>,
) -> Result<[Target; L]> {
    // connect values
    let (x, y, z) = ship;
    // range check ship head
    less_than_10(x, builder)?;
    less_than_10(y, builder)?;
    // build ship placement coordinate array
    let coordinates = builder.add_virtual_target_arr::<L>();
    for i in 0..L {
        let coordinate = generate_coordiante(x, y, z, i, builder)?;
        // println!("coordinate = {:?}", coordinate.);
        builder.connect(coordinate, coordinates[i]);
    }
    Ok(coordinates)
}

/**
 * Constructs an equation where the output will only be 1 if the input is one of the values in coordinates
 *
 * @param value - the value being checked for membership in coordinates
 * @param coordinate - values that should return 1 if inputted
 * @param builder - circuit builder
 * @return - expression that evaluates whether input is in coordinates
 */
pub fn interpolate_bitflip_bool<const L: usize>(
    value: Target,
    coordiantes: [Target; L],
    builder: &mut CircuitBuilder<F, D>,
) -> Result<BoolTarget> {
    // starting eq to check 1 = 0
    let mut exp_t = builder.constant(F::ONE);
    // iterate over coordinates to check identity of target
    for i in 0..L {
        // copy coordinate
        let coordinate_t = builder.add_virtual_target();
        builder.connect(coordiantes[i], coordinate_t);
        // check additive identity
        let checked_t = builder.sub(coordinate_t, value);
        // multiply against expression to interpolate bool
        exp_t = builder.mul(exp_t, checked_t);
    }
    // check if interpolated expression = 0
    let zero_t = builder.constant(F::ZERO);
    Ok(builder.is_equal(exp_t, zero_t))
}

/**
 * Given a ship and board, constrain the placement of the ship
 * @dev prevent overlapping ships
 *
 * @param ship - ship instantiation coordinates
 * @param board - board state as a 100 bit vector
 * @param builder - circuit builder
 * @return - new board state as 100 bit vector with ship coordinates bitflipped
 */
pub fn place_ship<const L: usize>(
    ship: (Target, Target, BoolTarget),
    board: Vec<Target>,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<Vec<Target>> {
    // construct the ship placement coordinates
    // @notice: range checks placement
    let ship_coordinates = ship_to_coordinates::<L>(ship, builder)?;

    // check that coordinates occupied by new ship are available
    let zero_t = builder.constant(F::ZERO);
    for i in 0..L {
        // access coordinate from bitmap
        println!("hi: {:?}", ship_coordinates[i]);
        let coordinate = builder.random_access(ship_coordinates[i], board.clone());
        println!("q: {:?}", coordinate);
        // constrain bit to be empty
        builder.connect(coordinate, zero_t);
    }

    // build new board state
    let one_t = builder.constant(F::ONE);
    let board_out = builder.add_virtual_targets(100);
    println!("y");
    for i in 0..100 {
        // constant for index access
        let index = builder.constant(F::from_canonical_u8(i as u8));
        // access coordinate from board bitvec representation
        println!("x");
        let coordinate = builder.random_access(index, board.clone());
        println!("y");

        // compute flipped bit value
        let flipped = builder.add(coordinate, one_t);
        // compute boolean evaluation of whether bit should be flipped
        let should_flip = interpolate_bitflip_bool::<L>(index, ship_coordinates, builder)?;
        // multiplex bit for new board state
        let board_out_coordinate = builder.select(should_flip, flipped, coordinate);
        // copy constrain construction of board output
        builder.connect(board_out_coordinate, board_out[i]);
    }
    
    Ok(board_out)
}

// use ensure to check constraints
// pub fn place_ship() -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let mut builder = CircuitBuilder::<F, D>::new(config);

//     let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
//     Ok(())
// }

#[cfg(test)]
mod tests {
    use plonky2::field::types::PrimeField64;

    use super::*;

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
        let board_pre: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

        // decompose into bits
        let bits = decompose_board(board_pre, &mut builder).unwrap();
        println!("bits: {:?}", bits);
        // proof inputs
        let board = [10u64, 20];
        let mut pw = PartialWitness::new();
        pw.set_target(board_pre[0], F::from_canonical_u64(board[0]));
        pw.set_target(board_pre[1], F::from_canonical_u64(board[0]));

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        // verify board placement
        let res = data.verify(proof);
        println!("yay: {:?}", res);
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
    pub fn test_place_ship() {
        // config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let board = builder.add_virtual_target_arr::<2>();
        let ship: (Target, Target, BoolTarget) = {
            let x = builder.add_virtual_target();
            let y = builder.add_virtual_target();
            let z = builder.add_virtual_bool_target_safe();
            (x, y, z)
        };
        println!("xXXX: {:?}", F::characteristic());

        
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
