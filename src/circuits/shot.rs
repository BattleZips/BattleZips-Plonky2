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
 * Constrain the computation of a shot coordinate into the serialized index
 * 
 * @param x - x coordinate of shot 
 * @param y - y coordinate of shot
 * @param builder - circuit builder
 * @return - serialized shot coordinate (10y + x)
 */
pub fn serialize_shot(
    x: Target,
    y: Target,
    builder: &mut CircuitBuilder<F, D>,
) -> Result<Target> {
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

#[cfg(test)]
mod tests {
    use plonky2::field::types::PrimeField64;

    use super::*;
    use crate::utils::{board::Board, ship::Ship};

    // #[test]
    // fn test_compute_ship_placement_target_indexes() {
    //     let ship = [Target::new(0), Target::new(1), Target::new(2)];
    //     let targets = compute_ship_placement_target_indexes::<3>(ship);
    //     println!("targets = {:?}", targets);
    // }

    #[test]
    fn test_shot() {
        // config
        let config = CircuitConfig::standard_recursion_config();
        let mut builder = CircuitBuilder::<F, D>::new(config);

        // targets
        let board_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();
        let shot_t: [Target; 2] = builder.add_virtual_targets(2).try_into().unwrap();

        // serialize shot coordinate
        let serialized_t = serialize_shot(shot_t[0], shot_t[1], &mut builder).unwrap();

        // check for hit or miss
        let hit = check_hit(board_t, serialized_t, &mut builder).unwrap();

        // proof inputs
        let board = Board::new(
            Ship::new(3, 4, false),
            Ship::new(9, 6, true),
            Ship::new(0, 0, false),
            Ship::new(0, 6, false),
            Ship::new(6, 1, true),
        );
        let board_canonical = board.canonical();
        let shot = [0, 0];

        // witness inputs
        let mut pw = PartialWitness::new();
        pw.set_target(board_t[0], F::from_canonical_u64(board_canonical[0]));
        pw.set_target(board_t[1], F::from_canonical_u64(board_canonical[0]));
        pw.set_target(shot_t[0], F::from_canonical_u64(shot[0]));
        pw.set_target(shot_t[1], F::from_canonical_u64(shot[1]));
        //@dev: export hit directly
        builder.register_public_input(hit);

        // prove board placement
        let data = builder.build::<C>();
        let proof = data.prove(pw).unwrap();

        // verify board placement
        data.verify(proof.clone()).unwrap();
        println!("proof verified: ");

        // print hit evaluation
        println!("hit: {:?}", proof.clone().public_inputs[0].to_canonical());
    }

}
