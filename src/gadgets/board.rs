use crate::circuits::{D, F};
use anyhow::Result;
use plonky2::{
    iop::target::{Target, BoolTarget},
    hash::{
        hash_types::HashOutTarget,
        poseidon::PoseidonHash,
    },
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