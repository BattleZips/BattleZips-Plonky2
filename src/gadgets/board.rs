use crate::circuits::{D, F};
use anyhow::Result;
use plonky2::{
    iop::target::{BoolTarget, Target},
    plonk::circuit_builder::CircuitBuilder,
};

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
        let back = builder.le_sum(bool_t[64..128].iter());
        [front, back]
    };
    Ok(composed_t)
}
