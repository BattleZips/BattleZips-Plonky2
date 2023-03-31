use crate::circuits::{D, F};
use anyhow::Result;
use plonky2::{
    field::types::Field,
    iop::target::{Target, BoolTarget},
    hash::{
        hash_types::HashOutTarget,
        poseidon::PoseidonHash,
    },
    plonk::circuit_builder::CircuitBuilder,
};
use super::range::less_than_10;

/**
 * Decompose serialized u128 into 100 LE bits
 *
 * @param board - u128 target to decompose
 * @param builder - circuit builder
 * @return - ordered 100 target bits representing private board state
 */
pub fn decompose_board(
    board: [Target; 2],
    builder: &mut CircuitBuilder<F, D>,
) -> Result<Vec<Target>> {
    // define virtual
    let bits = {
        let front = builder.split_le_base::<2>(board[0], 64);
        let back = builder.split_le_base::<2>(board[1], 64);
        front.iter().chain(back.iter()).copied().collect::<Vec<_>>()
    };

    Ok(bits)
}

/**
 * Recompose 100 LE bits into serialized u128
 *
 * @param board - 100 LE bits representing private board state
 * @param builder - circuit builder
 * @return - u128 target representing private board state
 */
pub fn recompose_board(
    board: Vec<Target>,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<[Target; 2]> {
    let bool_t: Vec<BoolTarget> = board
        .iter()
        .map(|bit| BoolTarget::new_unsafe(*bit))
        .collect();
    let composed_t: [Target; 2] = {

        let front = builder.le_sum(bool_t[0..64].iter());
        println!("front: {:?}", front);
        let back = builder.le_sum(bool_t[64..128].iter());
        println!("back: {:?}", back);

        [front, back]
    };
    Ok(composed_t)
}

/**
 * Given the canonical representation of board state, return the hash of the board state
 * @todo: add private salt to hash
 * 
 * @param board - u128 target representing private board state in LE
 * @param builder - circuit builder
 * @return - target of constrained computation of board hash
 */
pub fn hash_board(
    board: [Target; 2],
    builder: &mut CircuitBuilder<F, D>,
) -> Result<HashOutTarget> {
    let hash = builder.hash_n_to_hash_no_pad::<PoseidonHash>(board.try_into().unwrap());
    Ok(hash)
}

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
) -> Result<Target> {
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
        let coordinate = builder.random_access(ship_coordinates[i], board.clone());
        // constrain bit to be empty
        builder.connect(coordinate, zero_t);
    }

    // build new board state
    let one_t = builder.constant(F::ONE);
    let board_out = builder.add_virtual_targets(128);
    for i in 0..100 {
        // constant for index access
        let index = builder.constant(F::from_canonical_u8(i as u8));
        // access coordinate from board bitvec representation
        let coordinate = builder.random_access(index, board.clone());
        // compute flipped bit value
        let flipped = builder.add(coordinate, one_t);
        // compute boolean evaluation of whether bit should be flipped
        let should_flip = interpolate_bitflip_bool::<L>(index, ship_coordinates, builder)?;
        // multiplex bit for new board state
        let board_out_coordinate = builder.select(should_flip, flipped, coordinate);
        // copy constrain construction of board output
        builder.connect(board_out_coordinate, board_out[i]);
    }
    for i in 100..128 {
        // copy constrain construction of board output
        builder.connect(board[i], board_out[i]);
    }
    // return new board state
    Ok(board_out)
}