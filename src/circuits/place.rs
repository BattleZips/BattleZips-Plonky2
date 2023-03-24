use anyhow::Result;
use plonky2::{
    field::{extension::Extendable, goldilocks_field::GoldilocksField, types::Field},
    hash::hash_types::RichField,
    iop::{
        target::{Target, BoolTarget},
        witness::{PartialWitness, WitnessWrite},
    },
    plonk::{
        circuit_builder::CircuitBuilder,
        circuit_data::{CircuitConfig, VerifierCircuitData, VerifierCircuitTarget},
        config::{GenericConfig, PoseidonGoldilocksConfig},
        proof::ProofWithPublicInputs,
    },
};

const D: usize = 2;
type C = PoseidonGoldilocksConfig;
type F = <C as GenericConfig<D>>::F;

// L: length of ship placement
pub struct ShipPlacementTargets<const L: usize> {
    board_pre: [Target; 2],
    board_post: [Target; 2],
    ship: [Target; 3], // x, y, z
}

// pub fn compute_ship_placement_target_indexes<const L: usize>(ship: [Target; 3]) -> Result<()> {
//     let config = CircuitConfig::standard_recursion_config();
//     let pw = PartialWitness::new();
//     let mut builder = CircuitBuilder::<F, D>::new(config);
//     let limbs = {
//         let front = builder.split_le(board_pre[0], 64);
//         let back = builder.split_le(board_pre[1], 64);
//         front
//     };
//     println!("limbs = {:?}", limbs);
//     Ok(())
// }

/**
 * Given an existing target value, ensure that it is less than 10
 * 
 * @param value - assigned value being queried for range
 * @param builder - circuit builder
 * @return - range check enforced by permutation argument comparison with zero 
 */
pub fn less_than_10(value: Target, builder: &mut CircuitBuilder<F, D>) -> Result<()> {
    let mut exp = builder.constant(F::ONE);
    for i in 0..9 {
        // copy value being compared
        let value_t = builder.add_virtual_target();
        builder.connect(value, value_t);
        // constant being checked for range equality
        let range_t = builder.constant(F::from_canonical_u8(i));
        // subtract value against constant to demonstrate range
        let checked_t = builder.sub(range_t, value_t);
        // multiply against range check expression
        exp = builder.mul(exp, checked_t);
    }
    // check whether value is within range of 10
    let zero = builder.constant(F::ZERO);
    builder.connect(exp, zero);
    // return the 
    Ok(())
}

pub fn ship_to_coordinates<const L: usize>(ship: (Target, Target, BoolTarget), builder: &mut CircuitBuilder<F, D>) -> Result<[Target; L]> {
    let (x, y, z) = ship;
    // range check ship head
    // @TODO
    // build ship placement coordinate array
    let mut coordinates = builder.add_virtual_target_arr::<L>();
    for i in 0..L {
        // copy ship head coordinate
        let x_t = builder.add_virtual_target();
        builder.connect(x, x_t);
        let y_t = builder.add_virtual_target();
        builder.connect(y, y_t);
        
        let z_t = builder.select(z, ship.0 + i, ship.0);

        builder.select(z, x, y);
        let y = builder.if_else(ship.2, ship.1, ship.1 + i);
        let coordinates = y * 10 + x;
    };
    // let mut coordinates = [Target::new(0); L];
    // for i in 0..L as u8 {
    //     let x = builder.if_else(ship.2, ship.0 + i, ship.0);
    //     let y = builder.if_else(ship.2, ship.1, ship.1 + i);
    //     coordinates[i as usize] = y * 10 + x;
    // }
    // Ok(coordinates)
}

pub fn decompose_board(board: [Target; 2], builder: &mut CircuitBuilder<F, D>) -> Result<[BoolTarget; 100]> {
    // define virtual 
    let bits = {
        let front = builder.split_le(board[0], 64);
        let back = builder.split_le(board[1], 36);
        front.iter().chain(back.iter()).copied().collect::<Vec<_>>()
    };

    Ok(bits.try_into().unwrap())
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
        const D: usize = 2;
        type C = PoseidonGoldilocksConfig;
        type F = <C as GenericConfig<D>>::F;
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
}
