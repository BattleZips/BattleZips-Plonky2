use super::{board::decompose_board, range::less_than_10};
use crate::circuits::{D, F};
use anyhow::Result;
use plonky2::{field::types::Field, iop::target::Target, plonk::circuit_builder::CircuitBuilder};

/**
 * Constrain the computation of a shot coordinate into the serialized index
 *
 * @param x - x coordinate of shot
 * @param y - y coordinate of shot
 * @param builder - circuit builder
 * @return - serialized shot coordinate (10y + x)
 */
pub fn serialize_shot(x: Target, y: Target, builder: &mut CircuitBuilder<F, D>) -> Result<Target> {
    // ensure x and y are within range of 10
    less_than_10(x, builder)?;
    less_than_10(y, builder)?;
    // serialize shot coordinate
    let ten = builder.constant(F::from_canonical_u8(10));
    let y_serialized = builder.mul(y, ten);
    let serialized = builder.add(x, y_serialized);
    Ok(serialized)
}

/**
 * Constrains the lookup of a position on the board to return whether or not it is occupied by a ship
 *
 * @param board - serialized u128 representing private board state
 * @param shot - serialized shot coordinate (10y + x)
 * @param return - boolean target representing whether or not the shot coordinate is occupied
 */
pub fn check_hit(
    board: [Target; 2],
    shot: Target,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<Target> {
    // decompose board into bits
    let bits = decompose_board(board, builder)?;
    // access board state by index (shot coordinate)
    let hit = builder.random_access(shot, bits);
    Ok(hit)
}
